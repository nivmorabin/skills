"""probe2v_loopy_source.py — Find loopy.server source files and grep for the
actorId binding logic.

Specifically: where does the harness map (request body actorId / runtimeUserId / nothing)
to (Strands AgentCoreMemoryConfig.actor_id / boto3 create_event actorId / namespace
template substitution)?
"""
import os, sys, glob

print("== LOOPY SOURCE LOCATION ==")
candidates = [
    '/opt/amazon/python3.10/lib/python3.10/site-packages/loopy',
    '/opt/amazon/lib/python3.10/site-packages/loopy',
    '/opt/amazon/python3.10/lib/loopy',
]
loopy_root = None
for c in candidates:
    if os.path.isdir(c):
        loopy_root = c
        break

if not loopy_root:
    # Search more broadly
    for base in ['/opt/amazon', '/usr/local/lib', '/usr/lib']:
        for root, dirs, files in os.walk(base):
            if 'loopy' in dirs:
                loopy_root = os.path.join(root, 'loopy')
                break
        if loopy_root: break

print(f"LOOPY_ROOT={loopy_root}")
if not loopy_root:
    print("== NO LOOPY FOUND ==")
    sys.exit(0)

# List the top-level files
files = []
for root, dirs, fnames in os.walk(loopy_root):
    for fn in fnames:
        if fn.endswith('.py'):
            files.append(os.path.join(root, fn))
print(f"LOOPY_PY_FILES_COUNT={len(files)}")
for f in sorted(files)[:60]:
    print(f"  {f}")

# Grep for memory/actorId-binding logic
print("\n== GREP: actor_id assignment in loopy ==")
patterns = [
    'actor_id =',
    'actorId =',
    'actor_id=',
    'actorId=',
    '"default"',
    "'default'",
    'AgentCoreMemoryConfig',
    'agentCoreMemoryConfiguration',
    'runtimeUserId',
    'runtime_user_id',
    'create_event',
    'retrieve_memories',
    'namespaceTemplate',
]
for f in files:
    try:
        content = open(f).read()
    except Exception:
        continue
    fname = f.replace(loopy_root, 'loopy')
    for p in patterns:
        for ln_no, line in enumerate(content.split('\n'), 1):
            if p in line and 'def ' not in line[:line.find(p)] and len(line) < 200:
                # Limit per pattern to 2 lines per file to keep output bounded
                print(f"  {fname}:{ln_no}: {line.strip()[:180]}")
                break

print("\n== GREP: 'default' in loopy (only if mentions actor) ==")
for f in files:
    try:
        content = open(f).read()
    except Exception:
        continue
    fname = f.replace(loopy_root, 'loopy')
    for ln_no, line in enumerate(content.split('\n'), 1):
        if ('default' in line.lower() and 'actor' in line.lower()) or ('actor' in line and ('"default"' in line or "'default'" in line)):
            print(f"  {fname}:{ln_no}: {line.strip()[:200]}")

print("\n== DONE ==")
