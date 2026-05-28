"""probe2x — Can we modify loopy source on disk? Inspect mount, attempt write.

Tests in order of severity:
1. /proc/mounts — what mount options apply to /opt/amazon? (ro vs rw, overlay layers)
2. stat the target file — owner, perms, fs
3. open r+b — does the kernel allow it?
4. try to write a benign no-op (open/close in r+b without modifying bytes; abort if any change is needed) — proves write capability without actually corrupting
5. check pycache file (.pyc invalidation behavior)
"""
import os, sys, stat

TARGET = '/opt/amazon/lib/python3.10/site-packages/loopy/session/session_manager.py'
PYCACHE = '/opt/amazon/lib/python3.10/site-packages/loopy/session/__pycache__'
PARALLEL_NEW_FILE = '/opt/amazon/lib/python3.10/site-packages/loopy/session/_test_write.tmp'

print("== /proc/mounts grep amazon|opt|root ==")
try:
    for line in open('/proc/mounts').read().split('\n'):
        if 'amazon' in line or '/opt' in line or line.startswith('/ ') or line.startswith('overlay') or 'overlay' in line:
            print(f"  {line}")
except Exception as e:
    print(f"MOUNTS_ERR={e}")

print("\n== stat target ==")
try:
    st = os.stat(TARGET)
    print(f"  size={st.st_size} mode={oct(st.st_mode)} uid={st.st_uid} gid={st.st_gid}")
    print(f"  user_writable={bool(st.st_mode & stat.S_IWUSR)} group_writable={bool(st.st_mode & stat.S_IWGRP)} other_writable={bool(st.st_mode & stat.S_IWOTH)}")
except Exception as e:
    print(f"STAT_ERR={e}")

print("\n== whoami ==")
print(f"  uid={os.getuid()} gid={os.getgid()} euid={os.geteuid()}")

print("\n== try open r+b on the existing source ==")
try:
    with open(TARGET, 'r+b') as f:
        first = f.read(64)
        print(f"  OPEN_RW=ok first_64_bytes={first[:64]!r}")
except Exception as e:
    print(f"  OPEN_RW_ERR={type(e).__name__}: {str(e)[:200]}")

print("\n== try create a NEW file in same dir ==")
try:
    with open(PARALLEL_NEW_FILE, 'w') as f:
        f.write('test')
    print(f"  NEW_FILE_CREATE=ok")
    try:
        os.unlink(PARALLEL_NEW_FILE)
        print(f"  NEW_FILE_DELETE=ok")
    except Exception as e:
        print(f"  NEW_FILE_DELETE_ERR={e}")
except Exception as e:
    print(f"  NEW_FILE_CREATE_ERR={type(e).__name__}: {str(e)[:200]}")

print("\n== pycache contents ==")
try:
    for fn in sorted(os.listdir(PYCACHE)):
        full = os.path.join(PYCACHE, fn)
        st = os.stat(full)
        print(f"  {fn}  size={st.st_size}  mtime={st.st_mtime}")
except Exception as e:
    print(f"  PYCACHE_ERR={e}")

print("\n== try open r+b on .pyc ==")
try:
    pyc = os.path.join(PYCACHE, 'session_manager.cpython-310.pyc')
    with open(pyc, 'r+b') as f:
        first = f.read(32)
        print(f"  PYC_OPEN_RW=ok first_32={first[:32]!r}")
except Exception as e:
    print(f"  PYC_OPEN_RW_ERR={type(e).__name__}: {str(e)[:200]}")

print("\n== fs type of /opt/amazon ==")
try:
    statfs = os.statvfs('/opt/amazon/lib/python3.10/site-packages/loopy/session')
    print(f"  f_flag={statfs.f_flag} (ST_RDONLY=1)")
    print(f"  f_bsize={statfs.f_bsize}")
    print(f"  ro_bit_set={(statfs.f_flag & 1) == 1}")
except Exception as e:
    print(f"  STATVFS_ERR={e}")

print("\n== overlay/upper/lower hints ==")
try:
    for line in open('/proc/self/mountinfo').read().split('\n'):
        if 'amazon' in line or 'overlay' in line.lower():
            print(f"  {line[:200]}")
except Exception as e:
    print(f"  MOUNTINFO_ERR={e}")

print("\n== DONE ==")
