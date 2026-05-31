"""
probe_loopy_config_dump.py — Stage 2.5 of 11-3-loopy-process-recon.

Reads the most informative loopy source files in full + dumps utility
files. Specifically targets:
  - config.py (env var enumeration)
  - util/clients.py (preprod / gamma stage URLs, workload-token resolver)
  - util/constants.py (hardcoded constants, often including unknown env names)
  - tools/tool_provider.py (resolve_header_references / ARN substitution)
  - api_model/generated.py (regex patterns reveal undocumented ARN shapes — head only, file is 44KB)
  - container/ctr_container_manager.py (ctr argv shape — most informative for legacy escape)

Read-only. Authorized research; account owner is the test target.
"""

import os
import sys
import base64
from pathlib import Path


LOOPY_DIR = '/opt/amazon/lib/python3.10/site-packages/loopy'

TARGETS = [
    ('config.py', 12 * 1024),
    ('util/clients.py', 12 * 1024),
    ('util/constants.py', 8 * 1024),
    ('util/arn.py', 4 * 1024),
    ('tools/tool_provider.py', 16 * 1024),
    ('tools/gateway.py', 12 * 1024),
    ('tools/shell.py', 4 * 1024),
    ('tools/code_interpreter.py', 4 * 1024),
    ('tools/browser.py', 6 * 1024),
    ('container/ctr_container_manager.py', 16 * 1024),
    ('container/local_container_manager.py', 6 * 1024),
    ('handler/invoke.py', 16 * 1024),
    ('handler/invoke_agent_runtime_command.py', 4 * 1024),
    ('skills/fetcher.py', 14 * 1024),
    ('model/model_provider.py', 16 * 1024),
    ('model/mantle_compat.py', 4 * 1024),
    ('session/session_manager.py', 16 * 1024),
    ('api_model/request.py', 6 * 1024),
    ('abstract.py', 4 * 1024),
]


def _b64(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.b64encode(data).decode()


def _safe_read(path, max_bytes):
    try:
        with open(path, 'rb') as f:
            return f.read(max_bytes)
    except Exception as e:
        return f'<read-error:{type(e).__name__}:{e}>'.encode()


def main():
    print('PROBE=loopy-config-dump v1')
    if not os.path.isdir(LOOPY_DIR):
        print(f'LOOPY_DIR_MISSING={LOOPY_DIR}')
        print('END')
        return

    for rel, max_bytes in TARGETS:
        full = os.path.join(LOOPY_DIR, rel)
        data = _safe_read(full, max_bytes)
        print(f'FILE[{rel}]:LEN={len(data)}:{_b64(data)}')

    # Also: the api_model/generated.py head (it's 44KB, full dump too big)
    api_path = os.path.join(LOOPY_DIR, 'api_model/generated.py')
    api_data = _safe_read(api_path, 24 * 1024)
    print(f'FILE[api_model/generated.py-head]:LEN={len(api_data)}:{_b64(api_data)}')

    print('END')


if __name__ == '__main__':
    main()
