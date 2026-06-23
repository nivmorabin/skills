"""Blog demo — runtime environment recon.

Shows what the harness microVM looks like from the shell tool's perspective:
identity, process tree, filesystem layout, PID 1 identity, installed packages.

No env vars needed. No exfil. Pure recon for blog screenshots.

Hosted at github.com/nivmorabin/skills/dict-walk/pid1_runtime_recon.py
"""
import os
import subprocess


def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=5).decode('utf-8', errors='replace').strip()
    except Exception:
        return '(unavailable)'


def main():
    print('=== IDENTITY ===')
    print(run('id'))

    print('\n=== PROCESS TREE ===')
    print(run('ps aux 2>/dev/null || ps -ef'))

    print('\n=== FILESYSTEM ROOT ===')
    print(run('ls -la /'))

    print('\n=== /opt/amazon (harness runtime) ===')
    print(run('ls -la /opt/amazon/ 2>/dev/null'))

    print('\n=== PYTHON PACKAGES (selected) ===')
    pkg_dir = '/opt/amazon/lib/python3.10/site-packages'
    if os.path.isdir(pkg_dir):
        entries = sorted(os.listdir(pkg_dir))
        keywords = ('strands', 'loopy', 'httpx', 'boto', 'pydantic', 'mcp', 'uvicorn', 'starlette')
        matched = [e for e in entries if any(k in e.lower() for k in keywords)]
        for pkg in matched[:20]:
            print(f'  {pkg}')
        print(f'  ({len(entries)} total packages)')
    else:
        print('  (site-packages dir not found)')

    print('\n=== PID 1 CMDLINE ===')
    try:
        cmdline = open('/proc/1/cmdline', 'rb').read().replace(b'\x00', b' ').decode('utf-8', errors='replace').strip()
        print(f'  {cmdline}')
    except Exception as e:
        print(f'  (error: {e})')

    print('\n=== PID 1 STATUS ===')
    try:
        status = open('/proc/1/status').read()
        for line in status.splitlines():
            if line.startswith(('Name:', 'Uid:', 'Gid:', 'Seccomp:', 'NoNewPrivs:', 'CapBnd:')):
                print(f'  {line}')
    except Exception as e:
        print(f'  (error: {e})')

    print('\n=== /proc/1/mem ACCESS ===')
    print(f'  readable: {os.access("/proc/1/mem", os.R_OK)}')
    print(f'  writable: {os.access("/proc/1/mem", os.W_OK)}')

    print('\n=== DONE ===')


if __name__ == '__main__':
    main()
