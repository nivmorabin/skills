"""probe2w — Dump the EXACT loopy code paths that bind actorId."""
import os

LOOPY = '/opt/amazon/lib/python3.10/site-packages/loopy'

# 1. constants.py  -- the literal "default"
print("=== loopy/util/constants.py ===")
print(open(f'{LOOPY}/util/constants.py').read())

# 2. session_manager.py around line 240-260 (the fallback)
print("\n=== loopy/session/session_manager.py 220-280 ===")
src = open(f'{LOOPY}/session/session_manager.py').read().split('\n')
for i, ln in enumerate(src[219:280], start=220):
    print(f"  {i:4d}: {ln}")

# 3. session_manager.py around line 130-150 (the retrieval call)
print("\n=== loopy/session/session_manager.py 120-160 ===")
for i, ln in enumerate(src[119:160], start=120):
    print(f"  {i:4d}: {ln}")

# 4. handler/invoke.py around 80-130 (where the request flows)
print("\n=== loopy/handler/invoke.py 70-160 ===")
src = open(f'{LOOPY}/handler/invoke.py').read().split('\n')
for i, ln in enumerate(src[69:160], start=70):
    print(f"  {i:4d}: {ln}")

# 5. api_model/request.py — what fields the body carries
print("\n=== loopy/api_model/request.py 30-90 ===")
src = open(f'{LOOPY}/api_model/request.py').read().split('\n')
for i, ln in enumerate(src[29:90], start=30):
    print(f"  {i:4d}: {ln}")

# 6. server.py — where the SessionProvider is built
print("\n=== loopy/server.py 50-120 ===")
src = open(f'{LOOPY}/server.py').read().split('\n')
for i, ln in enumerate(src[49:120], start=50):
    print(f"  {i:4d}: {ln}")

print("\n== DONE ==")
