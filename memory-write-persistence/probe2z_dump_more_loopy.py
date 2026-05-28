"""probe2z — Dump invoke_agent_runtime_command.py + generated.py + skills/fetcher.py
to look for OTHER actorId binding paths we haven't traced.
"""
import os

LOOPY = '/opt/amazon/lib/python3.10/site-packages/loopy'

print("=== loopy/handler/invoke_agent_runtime_command.py ===")
try:
    print(open(f'{LOOPY}/handler/invoke_agent_runtime_command.py').read())
except Exception as e:
    print(f"ERR={e}")

print("\n\n=== loopy/api_model/generated.py (first 8000 chars) ===")
try:
    src = open(f'{LOOPY}/api_model/generated.py').read()
    print(src[:8000])
    print(f"\n... TOTAL_LENGTH={len(src)}")
except Exception as e:
    print(f"ERR={e}")

print("\n\n=== loopy/api_model/generated.py — grep actor/runtime/user ===")
try:
    for ln_no, line in enumerate(open(f'{LOOPY}/api_model/generated.py').read().split('\n'), 1):
        if any(p in line for p in ['actor', 'Actor', 'runtimeUserId', 'runtime_user', 'userId', 'User']):
            print(f"  {ln_no:4d}: {line.strip()[:200]}")
except Exception as e:
    print(f"ERR={e}")

print("\n\n=== loopy/api_model/request.py (full, for reference) ===")
try:
    print(open(f'{LOOPY}/api_model/request.py').read())
except Exception as e:
    print(f"ERR={e}")

print("\n\n=== loopy/skills/fetcher.py (first 4000 chars) ===")
try:
    print(open(f'{LOOPY}/skills/fetcher.py').read()[:4000])
except Exception as e:
    print(f"ERR={e}")

print("\n\n=== loopy/util/clients.py — does it have any defaults / context ===")
try:
    print(open(f'{LOOPY}/util/clients.py').read()[:3000])
except Exception as e:
    print(f"ERR={e}")

print("\n\n=== global grep for runtimeUserId across loopy ===")
import glob
for path in glob.glob(f'{LOOPY}/**/*.py', recursive=True):
    try:
        for ln_no, line in enumerate(open(path).read().split('\n'), 1):
            if 'runtimeUserId' in line or 'runtime_user_id' in line:
                fname = path.replace(LOOPY, 'loopy')
                print(f"  {fname}:{ln_no}: {line.strip()[:200]}")
    except Exception:
        pass

print("\n=== global grep for actor_id (assignment context) across loopy ===")
for path in glob.glob(f'{LOOPY}/**/*.py', recursive=True):
    try:
        for ln_no, line in enumerate(open(path).read().split('\n'), 1):
            if ('actor_id' in line or 'actorId' in line) and ('=' in line or 'def ' in line):
                fname = path.replace(LOOPY, 'loopy')
                if len(line) < 220:
                    print(f"  {fname}:{ln_no}: {line.strip()[:200]}")
    except Exception:
        pass

print("\n== DONE ==")
