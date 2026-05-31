"""
probe_loopy_source_args.py — Stage 2 of 11-3-loopy-process-recon.

Inspects the on-disk loopy.server source under
/opt/amazon/lib/python3.10/site-packages/loopy/ to characterize what argv
flags / env vars / config-file keys the server accepts but ISN'T being
passed in the live cmdline. Goal: surface internal endpoints, fleet creds,
role ARNs, debug-mode flags, or any other AWS-internal configuration the
deployed shape leaves at default.

Read-only. Authorized research; account owner is the test target.

Output: line-delimited base64-encoded markers.
  PROBE=loopy-source-args v1
  LOOPY_PKG_FILES=<count>:<base64-of-recursive-listing-with-sizes>
  LOOPY_INIT_HEAD=<base64-of-loopy/__init__.py-first-3000-bytes>
  LOOPY_SERVER_HEAD=<base64-of-loopy/server.py-or-__main__.py-first-5000-bytes>
  LOOPY_ENVVAR_REFS=<base64-of-grep-result-for-os.environ/getenv/os.getenv>
  LOOPY_ARGPARSE_DEFS=<base64-of-grep-result-for-argparse/click/typer/add_argument>
  LOOPY_CONFIG_REFS=<base64-of-grep-result-for-config-file-loading/yaml.load/toml.load/json.load>
  LOOPY_INTERNAL_URLS=<base64-of-grep-result-for-amazonaws.com/internal/aws-internal/genesis/cinc>
  LOOPY_ARN_REFS=<base64-of-grep-result-for-arn:aws:>
  LOOPY_HARDCODED_PORTS=<base64-of-grep-result-for-:48620/:8080/:1514/:1144>
  END
"""

import os
import sys
import base64
import subprocess
from pathlib import Path


LOOPY_PATH_CANDIDATES = [
    '/opt/amazon/lib/python3.10/site-packages/loopy',
    '/opt/amazon/lib/python3.10/site-packages/loopy_server',
    '/opt/amazon/python3.10/lib/python3.10/site-packages/loopy',
]


def _b64(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.b64encode(data).decode()


def _safe_read(path, max_bytes=8 * 1024):
    try:
        with open(path, 'rb') as f:
            return f.read(max_bytes)
    except Exception as e:
        return f'<read-error:{type(e).__name__}:{e}>'.encode()


def _find_loopy_dir():
    for cand in LOOPY_PATH_CANDIDATES:
        if os.path.isdir(cand):
            return cand
    # Last resort: scan site-packages for any 'loopy' dir.
    for sp in [
        '/opt/amazon/lib/python3.10/site-packages',
        '/opt/amazon/python3.10/lib/python3.10/site-packages',
    ]:
        if os.path.isdir(sp):
            for entry in os.listdir(sp):
                if 'loopy' in entry.lower():
                    full = os.path.join(sp, entry)
                    if os.path.isdir(full):
                        return full
    return None


def _list_files(loopy_dir, max_files=400):
    out_lines = []
    count = 0
    for root, dirs, files in os.walk(loopy_dir):
        # skip __pycache__
        dirs[:] = [d for d in dirs if d != '__pycache__']
        for f in files:
            if count >= max_files:
                break
            full = os.path.join(root, f)
            try:
                size = os.path.getsize(full)
            except Exception:
                size = -1
            rel = os.path.relpath(full, loopy_dir)
            out_lines.append(f'{size:>10} {rel}')
            count += 1
        if count >= max_files:
            out_lines.append('... (truncated)')
            break
    return count, '\n'.join(out_lines)


def _grep_python(loopy_dir, patterns, max_bytes_total=20 * 1024):
    """Grep all .py files under loopy_dir for any of the patterns. Returns
    a string of lines (file:lineno: matched line) capped at max_bytes_total.
    """
    out = []
    total = 0
    for root, dirs, files in os.walk(loopy_dir):
        dirs[:] = [d for d in dirs if d != '__pycache__']
        for f in files:
            if not f.endswith('.py'):
                continue
            full = os.path.join(root, f)
            rel = os.path.relpath(full, loopy_dir)
            try:
                with open(full, 'rb') as fh:
                    for i, line in enumerate(fh, 1):
                        try:
                            sline = line.decode('utf-8', errors='replace').rstrip()
                        except Exception:
                            continue
                        if any(p in sline for p in patterns):
                            entry = f'{rel}:{i}: {sline[:200]}'
                            out.append(entry)
                            total += len(entry)
                            if total >= max_bytes_total:
                                out.append('... (cap)')
                                return '\n'.join(out)
            except Exception:
                continue
    return '\n'.join(out)


def main():
    print('PROBE=loopy-source-args v1')
    loopy_dir = _find_loopy_dir()
    if not loopy_dir:
        print('LOOPY_DIR_NOT_FOUND=1')
        # Best-effort search of /opt for loopy-named files
        try:
            r = subprocess.run(
                ['find', '/opt', '-name', 'loopy*', '-maxdepth', '8',
                 '-type', 'd'],
                capture_output=True, text=True, timeout=10)
            print(f'LOOPY_FIND_OUT={_b64(r.stdout[:2000])}')
        except Exception as e:
            print(f'LOOPY_FIND_ERR={type(e).__name__}:{e}')
        print('END')
        return

    print(f'LOOPY_DIR={_b64(loopy_dir)}')
    count, listing = _list_files(loopy_dir)
    print(f'LOOPY_PKG_FILES={count}:{_b64(listing)}')

    # __init__ head
    init_path = os.path.join(loopy_dir, '__init__.py')
    print(f'LOOPY_INIT_HEAD={_b64(_safe_read(init_path, 3000))}')

    # __main__ / server entry candidates
    for entry in ('__main__.py', 'server.py', 'main.py', 'app.py',
                  'cli.py', 'run.py'):
        p = os.path.join(loopy_dir, entry)
        if os.path.isfile(p):
            print(f'LOOPY_ENTRY[{entry}]={_b64(_safe_read(p, 5000))}')

    # Argparse / click / typer references
    args_grep = _grep_python(loopy_dir, [
        'argparse', 'add_argument', 'click.', 'typer.', 'ArgumentParser',
        'Click(', '--', 'sys.argv',
    ])
    print(f'LOOPY_ARGPARSE_DEFS={_b64(args_grep)}')

    # Env-var reads
    env_grep = _grep_python(loopy_dir, [
        'os.environ', 'os.getenv', 'getenv(', 'environ.get',
    ])
    print(f'LOOPY_ENVVAR_REFS={_b64(env_grep)}')

    # Config-file reads
    cfg_grep = _grep_python(loopy_dir, [
        'yaml.load', 'yaml.safe_load', 'toml.load', 'tomli.load',
        'json.load(', 'configparser', 'ConfigParser', 'pydantic_settings',
        'BaseSettings', 'parse_file', 'from_file', 'load_config',
    ])
    print(f'LOOPY_CONFIG_REFS={_b64(cfg_grep)}')

    # Internal URLs / endpoints
    url_grep = _grep_python(loopy_dir, [
        'amazonaws.com', 'internal.', '-internal', 'aws-internal',
        'corp.amazon', 'amazon.com', 'genesis', 'cinc', 'kepler',
        'workload', 'identity', 'vault', 'mds.', 'mds:',
    ])
    print(f'LOOPY_INTERNAL_URLS={_b64(url_grep)}')

    # ARN refs
    arn_grep = _grep_python(loopy_dir, [
        'arn:aws:', 'arn:', '${arn:', 'role-arn', 'role_arn',
    ])
    print(f'LOOPY_ARN_REFS={_b64(arn_grep)}')

    # Hardcoded ports
    port_grep = _grep_python(loopy_dir, [
        '48620', '8080', '1514', '1144', '37185', '127.0.0.1',
        'localhost',
    ])
    print(f'LOOPY_HARDCODED_PORTS={_b64(port_grep)}')

    # Also look at /opt/amazon/bin/ for any loopy-launcher scripts
    try:
        for entry in os.listdir('/opt/amazon/bin'):
            if 'loopy' in entry.lower():
                full = os.path.join('/opt/amazon/bin', entry)
                if os.path.isfile(full):
                    data = _safe_read(full, 4000)
                    print(f'LOOPY_BIN[{entry}]={_b64(data)}')
    except Exception as e:
        print(f'LOOPY_BIN_ERR={type(e).__name__}:{e}')

    # And any systemd unit / config files referencing loopy
    try:
        r = subprocess.run(
            ['find', '/opt/amazon', '/etc', '/usr/local',
             '-name', '*loopy*', '-maxdepth', '6'],
            capture_output=True, text=True, timeout=15)
        print(f'LOOPY_FS_LOCATIONS={_b64(r.stdout[:3000])}')
    except Exception as e:
        print(f'LOOPY_FS_FIND_ERR={type(e).__name__}:{e}')

    print('END')


if __name__ == '__main__':
    main()
