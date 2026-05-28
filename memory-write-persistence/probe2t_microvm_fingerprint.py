"""probe2t_microvm_fingerprint.py — Print a microVM fingerprint.

If alice and bob run this and get the same fingerprint, they're hitting the
same microVM (same Linux boot, same PID 1 process). If different → microVM
pool-reuse is per-session and cross-user heap mutation is unreachable.
"""
import os, hashlib

print("== MICROVM FINGERPRINT ==")

# 1. Per-boot UUID — unique per Linux kernel boot
try:
    boot_id = open('/proc/sys/kernel/random/boot_id').read().strip()
    print(f"BOOT_ID={boot_id}")
except Exception as e:
    print(f"BOOT_ID_ERR={e}")

# 2. Hostname (microVM unique typically)
try:
    print(f"HOSTNAME={open('/etc/hostname').read().strip()}")
except Exception as e:
    print(f"HOSTNAME_ERR={e}")

# 3. PID 1 start time (column 22 of /proc/1/stat) — distinguishes process restarts
try:
    stat = open('/proc/1/stat').read().split()
    print(f"PID1_START_JIFFIES={stat[21]}")
    print(f"PID1_PID={stat[0]}")
except Exception as e:
    print(f"PID1_STAT_ERR={e}")

# 4. Cgroup path (container id)
try:
    cg = open('/proc/1/cgroup').read().strip()
    print(f"PID1_CGROUP={cg[:300]}")
except Exception as e:
    print(f"PID1_CGROUP_ERR={e}")

# 5. Uptime (microVMs' uptime drifts unless this is the same VM)
try:
    print(f"UPTIME={open('/proc/uptime').read().strip()}")
except Exception as e:
    print(f"UPTIME_ERR={e}")

# 6. PID 1 environ — does AWS_RUNTIME_SESSION_ID change per call?
try:
    env_raw = open('/proc/1/environ', 'rb').read()
    env = {}
    for entry in env_raw.split(b'\x00'):
        if b'=' in entry:
            k, v = entry.split(b'=', 1)
            env[k.decode(errors='replace')] = v.decode(errors='replace')
    for k in ['HOSTNAME', 'AWS_MEMORY_ARN', 'AWS_MEMORY_ACTOR_ID',
              'AWS_RUNTIME_SESSION_ID', 'AWS_SESSION_ID', 'RUNTIME_SESSION_ID']:
        v = env.get(k, '<not-set>')
        print(f"PID1_ENV[{k}]={v[:120]}")
except Exception as e:
    print(f"PID1_ENVIRON_ERR={e}")

# 7. Heap fingerprint — sample 32 KB from heap and hash. Same VM, same RAM
#    contents at this address → same hash. Useful as composite signal.
try:
    regions = []
    with open('/proc/1/maps', 'r') as f:
        for line in f:
            parts = line.split()
            if len(parts) < 5: continue
            perms = parts[1]
            path = parts[5] if len(parts) >= 6 else ''
            if perms.startswith('rw') and not path:
                a, b = parts[0].split('-')
                regions.append((int(a, 16), int(b, 16)))
    if regions:
        # Hash the FIRST 64KB of the FIRST anonymous rw region
        with open('/proc/1/mem', 'rb') as mem:
            mem.seek(regions[0][0])
            sample = mem.read(min(65536, regions[0][1] - regions[0][0]))
            print(f"HEAP_FIRST_REGION_ADDR={hex(regions[0][0])}")
            print(f"HEAP_SAMPLE_LEN={len(sample)}")
            print(f"HEAP_SAMPLE_SHA256={hashlib.sha256(sample).hexdigest()[:32]}")
except Exception as e:
    print(f"HEAP_FP_ERR={e}")

print("== END FINGERPRINT ==")
