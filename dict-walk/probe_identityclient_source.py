"""Pull the bedrock_agentcore.services.identity module source from the
harness microVM so we can characterize how it talks to Identity DP."""

import os
import sys
import base64
import subprocess


def _b64(d):
    if isinstance(d, str):
        d = d.encode()
    return base64.b64encode(d).decode()


def _safe_read(p, max_b=64 * 1024):
    try:
        with open(p, 'rb') as f:
            return f.read(max_b)
    except Exception as e:
        return f'<{type(e).__name__}:{e}>'.encode()


def main():
    print('PROBE=identityclient-source v1')
    # find the package
    candidates = [
        '/opt/amazon/lib/python3.10/site-packages/bedrock_agentcore',
        '/opt/amazon/python3.10/lib/python3.10/site-packages/bedrock_agentcore',
    ]
    base = None
    for c in candidates:
        if os.path.isdir(c):
            base = c
            break
    if not base:
        # search
        try:
            r = subprocess.run(
                ['python3', '-c',
                 'import bedrock_agentcore, os; print(os.path.dirname(bedrock_agentcore.__file__))'],
                capture_output=True, text=True, timeout=8)
            base = r.stdout.strip()
            print(f'PY_LOCATE={_b64(base.encode())}')
        except Exception as e:
            print(f'PY_LOCATE_ERR={type(e).__name__}:{e}')

    if not base or not os.path.isdir(base):
        print('NO_BASE=1')
        print('END')
        return
    print(f'BASE={_b64(base.encode())}')

    # walk the package, capture every .py up to 24KB each
    total = 0
    for root, dirs, files in os.walk(base):
        dirs[:] = [d for d in dirs if d != '__pycache__']
        for f in sorted(files):
            if not f.endswith('.py'):
                continue
            full = os.path.join(root, f)
            rel = os.path.relpath(full, base)
            data = _safe_read(full, 24 * 1024)
            total += len(data)
            if total > 600 * 1024:
                print(f'CAP_HIT_AT={_b64(rel.encode())}')
                print('END')
                return
            print(f'FILE[{rel}]:LEN={len(data)}:{_b64(data)}')
    print('END')


if __name__ == '__main__':
    main()
