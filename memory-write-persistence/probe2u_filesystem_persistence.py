"""probe2u_filesystem_persistence.py — does the harness filesystem persist across users?

Phase A (writer): write a unique marker file to /tmp and several other locations,
                   plus print the BOOT_ID.
Phase B (reader): read those marker files and print BOOT_ID for cross-correlation.

Mode is set via env: PROBE_MODE=write or PROBE_MODE=read
Marker text via env: PROBE_MARKER=<canary>
"""
import os, time

mode = os.environ.get('PROBE_MODE', 'read').strip()
marker = os.environ.get('PROBE_MARKER', 'p2u_default').strip()

try:
    boot_id = open('/proc/sys/kernel/random/boot_id').read().strip()
except Exception:
    boot_id = '?'
print(f"BOOT_ID={boot_id}")
print(f"MODE={mode}")
print(f"MARKER={marker}")

paths = ['/tmp/p2u_marker', '/dev/shm/p2u_marker', '/var/tmp/p2u_marker',
         '/run/p2u_marker', '/opt/amazon/p2u_marker']

if mode == 'write':
    for p in paths:
        try:
            with open(p, 'w') as f:
                f.write(f'{marker}|{boot_id}|{time.time()}\n')
            print(f"WROTE {p}")
        except Exception as e:
            print(f"WROTE_ERR {p}: {type(e).__name__}: {str(e)[:80]}")

elif mode == 'read':
    for p in paths:
        try:
            with open(p, 'r') as f:
                content = f.read().strip()
            print(f"READ {p}: {content}")
        except FileNotFoundError:
            print(f"READ {p}: (not present)")
        except Exception as e:
            print(f"READ_ERR {p}: {type(e).__name__}: {str(e)[:80]}")

print("== DONE ==")
