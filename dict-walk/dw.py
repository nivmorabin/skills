"""Dict-walk discovery — find the live system_prompt PyUnicodeObject.

Combined-table dicts store values directly in the key-entry structure:
  PyDictKeyEntry = { hash(8), me_key(8), me_value(8) }
So for each occurrence of a pointer to the PyUnicodeObject('_system_prompt')
in writable memory, the adjacent 8 bytes is the value — trivially read.

Split-table dicts (used for Python instance __dict__ since CPython 3.6)
share one PyDictKeysObject across many instances and store VALUES in a
per-instance ma_values array. The me_value slot is always NULL in the
shared keys structure. To resolve:
  1. Locate a candidate ma_values array (an 8-byte-aligned window of
     pointers in writable memory where at least one pointer dereferences
     to a PyUnicodeObject whose body is prompt-shaped).
  2. That prompt-shaped PyUnicodeObject IS the live instance value.

CPython 3.10 layouts (from Include/cpython/dictobject.h):
  PyDictObject:
     0: ob_refcnt / 8: ob_type / 16: ma_used / 24: ma_version_tag
    32: ma_keys (PyDictKeysObject*) / 40: ma_values (PyObject**)
"""
import os
import re
import pathlib
import struct


# Valid userspace pointer range on aarch64 Linux: ~0x100 up to 2^48.
MIN_PTR = 0x1000
MAX_PTR = 0x0000_ffff_ffff_ffff  # 48-bit VA


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
    if not is_valid_ptr(addr):
        return None
    mr = os.open('/proc/1/mem', os.O_RDONLY)
    try:
        try:
            os.lseek(mr, addr, 0)
        except (OverflowError, OSError):
            return None
        try:
            raw = os.read(mr, 8)
        except OSError:
            return None
        if len(raw) < 8:
            return None
        return struct.unpack_from('<Q', raw)[0]
    finally:
        os.close(mr)


def read_pyuni(header_addr, max_len=4000):
    """Read a candidate PyUnicodeObject at header_addr. Returns (length, body)
    or None if invalid."""
    if not is_valid_ptr(header_addr):
        return None
    mr = os.open('/proc/1/mem', os.O_RDONLY)
    try:
        try:
            os.lseek(mr, header_addr, 0)
        except (OverflowError, OSError):
            return None
        try:
            hdr = os.read(mr, 48)
        except OSError:
            return None
        if len(hdr) < 48:
            return None
        length = struct.unpack_from('<q', hdr, 16)[0]
        if length < 1 or length > max_len:
            return None
        body_addr = header_addr + 48
        if not is_valid_ptr(body_addr):
            return None
        try:
            os.lseek(mr, body_addr, 0)
            body = os.read(mr, length)
        except (OverflowError, OSError):
            return None
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


# -------------------- stage 3: combined-table deref --------------------
def try_combined(slot_addr):
    mv = read_qword(slot_addr + 8)
    if mv is None or mv == 0:
        return None
    if not is_valid_ptr(mv):
        return ('bad_ptr', mv)
    decoded = read_pyuni(mv)
    if decoded is None:
        return ('not_pyuni', mv)
    return ('ok', mv, decoded)


print('---STAGE 3: combined-table DEREF (up to 10 slots)---')
combined_good = 0
null_count = 0
try:
    for s in mekey_slots[:10]:
        try:
            result = try_combined(s)
        except Exception as e:
            print('  slot 0x%x try_combined_err: %s' % (s, e))
            continue
        if result is None:
            null_count += 1
            print('  slot 0x%x me_value=NULL (split-table — see stage 4)' % s)
            continue
        tag = result[0]
        if tag == 'bad_ptr':
            print('  slot 0x%x me_value=0x%x <out_of_range>' % (s, result[1]))
        elif tag == 'not_pyuni':
            print('  slot 0x%x me_value=0x%x <not-a-pyunicode>' % (s, result[1]))
        elif tag == 'ok':
            mv_addr, (L, body) = result[1], result[2]
            preview = body[:180].decode('utf-8', errors='replace')
            print('  slot 0x%x me_value=0x%x len=%d' % (s, mv_addr, L))
            print('    body: %r' % preview)
            combined_good += 1
except Exception as e:
    print('STAGE 3 crashed: %s' % e)

if len(mekey_slots) > 10:
    print('  ...and %d more slots' % (len(mekey_slots) - 10))
print('null_count=%d combined_good_deref=%d' % (null_count, combined_good))


# -------------------- stage 4: split-table values-array search --------------
# Heuristic: walk writable memory as candidate 16-pointer windows. Any
# window where at least one pointer dereferences to a PyUnicode whose body
# starts with "You are " and is >=40 bytes long is a candidate instance
# values array. The matching PyUnicodeObject IS the live prompt value.

print('---STAGE 4: split-table search (prompt-shaped string in values array) ---')
found_prompts = []
scan_budget = 500_000
windows_checked = 0
try:
    for lo, data in region_data.items():
        if windows_checked > scan_budget:
            break
        end = len(data) - 128
        mv = memoryview(data)
        off = 0
        while off <= end and windows_checked < scan_budget:
            # Fast-path: check if at least one ptr looks user-space-ish
            # before paying deref cost.
            any_interesting = False
            for k in range(16):
                p = struct.unpack_from('<Q', mv, off + k * 8)[0]
                if MIN_PTR <= p <= MAX_PTR:
                    any_interesting = True
                    break
            if any_interesting:
                for k in range(16):
                    p = struct.unpack_from('<Q', mv, off + k * 8)[0]
                    if not is_valid_ptr(p):
                        continue
                    try:
                        decoded = read_pyuni(p, max_len=2000)
                    except Exception:
                        continue
                    if decoded is None:
                        continue
                    L, body = decoded
                    if L >= 40 and body.startswith(b'You are '):
                        found_prompts.append({
                            'values_array_addr': lo + off,
                            'ptr_slot_in_array': k,
                            'prompt_ptr': p,
                            'prompt_len': L,
                            'prompt_body': body,
                        })
            windows_checked += 1
            off += 8
except Exception as e:
    print('STAGE 4 crashed: %s' % e)
print('windows_checked=%d prompt_candidates=%d' %
      (windows_checked, len(found_prompts)))

# Dedupe by prompt_ptr.
seen = {}
for f in found_prompts:
    seen.setdefault(f['prompt_ptr'], f)
for i, f in enumerate(list(seen.values())[:5]):
    preview = f['prompt_body'][:180].decode('utf-8', errors='replace')
    print('  [%d] values_array=0x%x ptr_slot=%d prompt_ptr=0x%x len=%d' % (
        i, f['values_array_addr'], f['ptr_slot_in_array'],
        f['prompt_ptr'], f['prompt_len']))
    print('      body: %r' % preview)
print('UNIQUE_PROMPT_STRINGS=%d' % len(seen))
