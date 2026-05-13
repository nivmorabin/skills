"""Notebook-14 §4.2 — PID 1 memory scan for vault-canary bytes.

Runs INSIDE the harness shell tool. Reads /proc/1/maps, iterates writable-
private anonymous regions (Python heap pages), scans each for the planted
canary, prints occurrence offsets and surrounding context.

Hosted at github.com/nivmorabin/skills/dict-walk/pid1_canary_scan.py and
fetched via `curl -sL <url> | python3` from the harness shell. Hosting it
externally bypasses LLM-mediated quoting traps (heredocs, base64-piping,
inline python3 -c) where the model retypes / mangles the script body.
"""
import os
import sys


CANARY = b'IDENT-APIKEY-CANARY-9F3E2B1A-DO-NOT-USE'
MAX_BYTES = 256 * 1024 * 1024


def main():
    # Parse /proc/1/maps; collect writable-private anonymous regions
    # (Python heap arenas, allocated dicts, str bodies, list buffers).
    # Reading /proc/1/mem at offset 0 always EIOs (the NULL page is unmapped),
    # so the readability sanity check happens AFTER we have a real mapped
    # address from /proc/1/maps.
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
                # Skip file-backed; we want anon heap pages.
                continue
            try:
                start_s, end_s = addr_range.split('-')
                start = int(start_s, 16)
                end = int(end_s, 16)
            except Exception:
                continue
            regions.append((start, end, line.rstrip()))

    print(f'WRITABLE_PRIVATE_ANON_REGIONS={len(regions)}')

    # Now that we have at least one real mapped address, sanity-check that
    # /proc/1/mem is actually readable from this process.
    if not regions:
        print('PROC1_MEM_READABLE=UNKNOWN (no writable regions to probe)')
        return
    try:
        with open('/proc/1/mem', 'rb') as f:
            f.seek(regions[0][0])
            _probe = f.read(16)
        print(f'PROC1_MEM_READABLE=YES (probed {len(_probe)} bytes at {hex(regions[0][0])})')
    except Exception as e:
        print(f'PROC1_MEM_READABLE=NO ({type(e).__name__}: {e})')
        return

    total_bytes = 0
    hit_regions = 0
    total_occurrences = 0

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
                # Some rw-p regions error on read (kernel-internal). Skip.
                continue
            total_bytes += size
            if CANARY not in chunk:
                continue

            # Found at least one. Enumerate offsets + context windows.
            offsets = []
            idx = -1
            while True:
                idx = chunk.find(CANARY, idx + 1)
                if idx < 0:
                    break
                offsets.append(idx)

            hit_regions += 1
            total_occurrences += len(offsets)

            print(
                f'CANARY_FOUND range_line={raw_line!r} '
                f'va_start={hex(start)} va_end={hex(end)} '
                f'count={len(offsets)} first_offsets={offsets[:5]}'
            )
            for off in offsets[:3]:
                window_start = max(0, off - 48)
                window_end = min(len(chunk), off + len(CANARY) + 48)
                ctx = chunk[window_start:window_end]
                print(f'  context_window: {ctx!r}')
            sys.stdout.flush()

    print(f'BYTES_SCANNED={total_bytes}')
    print(f'TOTAL_HIT_REGIONS={hit_regions}')
    print(f'TOTAL_HIT_OCCURRENCES={total_occurrences}')


if __name__ == '__main__':
    main()
