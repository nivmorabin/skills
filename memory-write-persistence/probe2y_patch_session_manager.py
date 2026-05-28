"""probe2y — Patch loopy/session/session_manager.py:248 to force DEFAULT_ACTOR_ID.

Original (line 248):
    self._actor_id = actor_id or DEFAULT_ACTOR_ID

Modified:
    self._actor_id = DEFAULT_ACTOR_ID  # patched-by-probe2y

This is the canonical "fallback line" — the one Python `or` that decides whether
the per-call body's actorId reaches Strands or is overridden by the literal
"default". If the patch survives PID 1 restart (and isn't isolated to this
container), the next invocation's session manager will pin every user to the
"default" actorId regardless of what they pass.

Modes:
  PROBE_MODE=patch     — apply the patch
  PROBE_MODE=restore   — restore the original
  PROBE_MODE=inspect   — read the current line 248 (no write)

Env:
  PROBE_CANARY — marker placed in a comment so we can detect persistence
"""
import os, sys

TARGET = '/opt/amazon/lib/python3.10/site-packages/loopy/session/session_manager.py'
ORIGINAL_LINE = '        self._actor_id = actor_id or DEFAULT_ACTOR_ID'
PATCHED_LINE  = '        self._actor_id = DEFAULT_ACTOR_ID  # patched-by-probe2y'
RESTORED_LINE = ORIGINAL_LINE

mode = os.environ.get('PROBE_MODE', 'inspect').strip()
canary = os.environ.get('PROBE_CANARY', 'p2y').strip()

print(f"P2Y_BOOT mode={mode} canary={canary}")

# Always snapshot current state first
try:
    with open(TARGET, 'r') as f:
        src = f.read()
    lines = src.split('\n')
    # Find the line by content (in case line numbers drift between deploys)
    target_idx = None
    for i, ln in enumerate(lines):
        if 'self._actor_id =' in ln and 'DEFAULT_ACTOR_ID' in ln:
            target_idx = i
            print(f"FOUND_LINE idx={i} text={ln!r}")
            break
    if target_idx is None:
        print("VERDICT=NO_TARGET_LINE_FOUND")
        sys.exit(1)
except Exception as e:
    print(f"READ_ERR={type(e).__name__}: {str(e)[:200]}")
    sys.exit(1)

current = lines[target_idx]
already_patched = 'patched-by-probe2y' in current

if mode == 'inspect':
    print(f"CURRENT_LINE={current!r}")
    print(f"ALREADY_PATCHED={already_patched}")
    print("VERDICT=INSPECT_ONLY")
    sys.exit(0)

if mode == 'patch':
    if already_patched:
        print(f"VERDICT=ALREADY_PATCHED canary={canary}")
        sys.exit(0)
    lines[target_idx] = PATCHED_LINE + f' canary={canary}'
    new_src = '\n'.join(lines)
    try:
        with open(TARGET, 'w') as f:
            f.write(new_src)
        print(f"PATCH_WRITE=ok new_line={lines[target_idx]!r}")
        # Verify the write
        with open(TARGET, 'r') as f:
            verify = f.read()
        if PATCHED_LINE in verify:
            print(f"PATCH_VERIFY=ok")
        else:
            print(f"PATCH_VERIFY=fail")
        # Delete pycache if any so next import picks up new source
        import shutil
        pyc_dir = os.path.dirname(TARGET) + '/__pycache__'
        if os.path.isdir(pyc_dir):
            shutil.rmtree(pyc_dir)
            print(f"PYCACHE_DELETED={pyc_dir}")
        else:
            print(f"PYCACHE_ABSENT={pyc_dir}")
        print(f"VERDICT=PATCHED canary={canary}")
    except Exception as e:
        print(f"PATCH_WRITE_ERR={type(e).__name__}: {str(e)[:200]}")

elif mode == 'restore':
    lines[target_idx] = RESTORED_LINE
    new_src = '\n'.join(lines)
    try:
        with open(TARGET, 'w') as f:
            f.write(new_src)
        print(f"RESTORE_WRITE=ok line={lines[target_idx]!r}")
        with open(TARGET, 'r') as f:
            verify = f.read()
        if 'actor_id or DEFAULT_ACTOR_ID' in verify and 'patched-by-probe2y' not in verify:
            print(f"RESTORE_VERIFY=ok")
        else:
            print(f"RESTORE_VERIFY=fail")
        import shutil
        pyc_dir = os.path.dirname(TARGET) + '/__pycache__'
        if os.path.isdir(pyc_dir):
            shutil.rmtree(pyc_dir)
            print(f"PYCACHE_DELETED={pyc_dir}")
        print(f"VERDICT=RESTORED")
    except Exception as e:
        print(f"RESTORE_WRITE_ERR={type(e).__name__}: {str(e)[:200]}")

print("== DONE ==")
