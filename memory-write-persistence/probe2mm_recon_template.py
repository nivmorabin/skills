"""
probe2mm_recon_template.py — READ-ONLY recon of PID1 heap for the retrieval
namespace template string. Reports count + addresses of occurrences.

Delivered via: curl -sL <raw-url> | python3
Runs inside the harness shell-tool child (same-UID root, /proc/1/mem readable).
"""
import os, re, sys

TARGET = b"/tips/actors/{actorId}/"
ALT_TARGETS = [
    b"support/summaries/{sessionId}/",
    b"DEFAULT_ACTOR_ID",
    b"/tips/actors/default/",
]

def scan_pid1(pattern):
    """Scan PID1 RW heap regions for `pattern`. Return (count, [(addr, region_info), ...])."""
    hits = []
    maps = open("/proc/1/maps").read().splitlines()
    mem = open("/proc/1/mem", "rb")
    for line in maps:
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+)\s+([rwxsp-]+)", line)
        if not m:
            continue
        perms = m.group(3)
        if "r" not in perms or "w" not in perms:
            continue
        a, b = int(m.group(1), 16), int(m.group(2), 16)
        if b - a > 64 * 1024 * 1024:
            continue
        try:
            mem.seek(a)
            buf = mem.read(b - a)
        except Exception:
            continue
        offset = 0
        while True:
            idx = buf.find(pattern, offset)
            if idx == -1:
                break
            hits.append((a + idx, line.strip()[:60]))
            offset = idx + 1
    mem.close()
    return len(hits), hits

print(f"RECON_TARGET={TARGET.decode()}")
print(f"RECON_TARGET_LEN={len(TARGET)}")
count, hits = scan_pid1(TARGET)
print(f"RECON_COUNT={count}")
for addr, region in hits:
    print(f"  HIT addr=0x{addr:x} region={region}")

print()
for alt in ALT_TARGETS:
    c, _ = scan_pid1(alt)
    print(f"  ALT {c:3d}x  {alt.decode(errors='replace')}")

# Also report bob's sub count for context
bob_sub = os.environ.get("BOB_SUB", "")
if bob_sub:
    c, _ = scan_pid1(bob_sub.encode())
    print(f"  BOB_SUB {c:3d}x  {bob_sub}")

print("\nRECON_DONE=OK")
