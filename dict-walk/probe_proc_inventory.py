"""
probe_proc_inventory.py — Stage 1 process inventory on the AgentCore Harness.

Purpose: enumerate every PID visible via /proc/*/ from the harness shell-tool
position. Read-only. No exfil; output goes via stdout → harness shell-tool's
JSON envelope → Bedrock event stream → laptop side parses.

Authorized research; account owner is the test target. Do not use elsewhere.

Output format: line-delimited markers, each line ASCII-clean. Laptop side
greps for the markers and parses fields.

Markers (one per line):
  PROBE=proc-inventory v1
  PID=<pid> UID=<uid> COMM=<comm> PPID=<ppid> EXE=<exe> CWD=<cwd>
  CMDLINE=<pid>:<cmdline-hex>
  ENV_HIT=<pid>:<key>:<value-truncated-to-200>
  FD_HIT=<pid>:<fd>:<target>
  IO=<pid>:<read_bytes>:<write_bytes>
  NET_TCP=<state>:<localaddr>:<remoteaddr>:<uid>:<inode>
  NET_UNIX=<inode>:<state>:<path>
  END
"""

import os
import sys
import glob
import binascii

# Patterns we care about for env / FD greps. Loopy-Identity-surface-aware
# (cite [[agentcore-loopy-identity-surface]]).
ENV_KEY_PATTERN = (
    'AWS_', 'TOKEN', 'KEY', 'SECRET', 'CREDS', 'IDENTITY', 'VAULT',
    'WORKLOAD', 'JWT', 'SESSION', 'ENDPOINT', 'AGENTCORE', 'LOOPY',
    'GENESIS', 'CINC', 'BEARER', 'ACCESS', 'AUTH'
)
FD_PATH_PATTERN = (
    '/mnt/', '/run/', 'vault', 'secret', 'creds', 'token',
    'identity', 'workload', '.sock', 'agentcoresessionstorage',
    'genesis', 'loopy', 'cinc', 'sessionstorage'
)


def _safe_read(path, max_bytes=64 * 1024):
    try:
        with open(path, 'rb') as f:
            return f.read(max_bytes)
    except Exception:
        return None


def _safe_readlink(path):
    try:
        return os.readlink(path)
    except Exception:
        return None


def _list_pids():
    out = []
    for entry in sorted(os.listdir('/proc')):
        if entry.isdigit():
            out.append(entry)
    return out


def _parse_status(status_bytes):
    fields = {}
    if not status_bytes:
        return fields
    for line in status_bytes.decode('utf-8', errors='replace').splitlines():
        if ':' in line:
            k, v = line.split(':', 1)
            fields[k.strip()] = v.strip()
    return fields


def _emit_pid(pid):
    status = _parse_status(_safe_read(f'/proc/{pid}/status'))
    uid = status.get('Uid', '?').split()[0] if status.get('Uid') else '?'
    ppid = status.get('PPid', '?')
    comm = (_safe_read(f'/proc/{pid}/comm') or b'').decode(
        'utf-8', errors='replace').strip()
    exe = _safe_readlink(f'/proc/{pid}/exe') or '?'
    cwd = _safe_readlink(f'/proc/{pid}/cwd') or '?'
    print(f'PID={pid} UID={uid} COMM={comm} PPID={ppid} EXE={exe} CWD={cwd}')

    # full cmdline as hex so we don't have to escape NULs / quotes
    cmdline = _safe_read(f'/proc/{pid}/cmdline') or b''
    if cmdline:
        print(f'CMDLINE={pid}:{binascii.hexlify(cmdline).decode()}')

    # environ — filtered grep
    environ = _safe_read(f'/proc/{pid}/environ') or b''
    if environ:
        for env_entry in environ.split(b'\x00'):
            if not env_entry:
                continue
            try:
                kv = env_entry.decode('utf-8', errors='replace')
            except Exception:
                continue
            if '=' not in kv:
                continue
            k, _, v = kv.partition('=')
            ku = k.upper()
            if any(p in ku for p in ENV_KEY_PATTERN):
                # Truncate value to 200 chars to avoid blowing up the LLM
                # response cap; still enough to spot tokens / endpoints.
                vt = v.replace('\n', '\\n').replace('\r', '\\r')[:200]
                print(f'ENV_HIT={pid}:{k}:{vt}')

    # FDs — filtered grep on the readlink target
    fd_dir = f'/proc/{pid}/fd'
    try:
        fds = os.listdir(fd_dir)
    except Exception:
        fds = []
    for fd in fds:
        target = _safe_readlink(f'{fd_dir}/{fd}') or ''
        tl = target.lower()
        if any(p in tl for p in FD_PATH_PATTERN) or target.startswith('socket:'):
            print(f'FD_HIT={pid}:{fd}:{target}')

    # io counters — Stage 2 baseline
    io = _safe_read(f'/proc/{pid}/io') or b''
    if io:
        rb = wb = '?'
        for line in io.decode('utf-8', errors='replace').splitlines():
            if line.startswith('read_bytes:'):
                rb = line.split(':', 1)[1].strip()
            elif line.startswith('write_bytes:'):
                wb = line.split(':', 1)[1].strip()
        print(f'IO={pid}:{rb}:{wb}')


def _emit_net():
    # Snapshot tcp / tcp6 / unix once. Dump only listening + established for
    # tcp, all for unix.
    for fname, label in (('/proc/net/tcp', 'tcp'), ('/proc/net/tcp6', 'tcp6')):
        data = _safe_read(fname)
        if not data:
            continue
        for i, line in enumerate(data.decode('utf-8', errors='replace').splitlines()):
            if i == 0:  # header
                continue
            parts = line.split()
            if len(parts) < 10:
                continue
            local, remote, state, _, _, _, _, uid, _, inode = parts[1:11]
            print(f'NET_{label.upper()}={state}:{local}:{remote}:{uid}:{inode}')

    data = _safe_read('/proc/net/unix')
    if data:
        for i, line in enumerate(data.decode('utf-8', errors='replace').splitlines()):
            if i == 0:
                continue
            parts = line.split()
            if len(parts) < 7:
                continue
            inode = parts[6]
            path = parts[7] if len(parts) > 7 else ''
            state = parts[5]
            print(f'NET_UNIX={inode}:{state}:{path}')


def main():
    print('PROBE=proc-inventory v1')
    pids = _list_pids()
    print(f'PID_COUNT={len(pids)}')
    for pid in pids:
        try:
            _emit_pid(pid)
        except Exception as e:
            print(f'PID_ERR={pid}:{type(e).__name__}:{e}')
    _emit_net()
    print('END')


if __name__ == '__main__':
    main()
