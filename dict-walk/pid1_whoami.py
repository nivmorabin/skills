"""Blog demo — quick recon: who are we inside the harness?

Shows: whoami, id, process tree, PID 1 details, /proc/1/mem access.
Clean terminal-style output with $ command prefixes.

No env vars needed.
Hosted at github.com/nivmorabin/skills/dict-walk/pid1_whoami.py
"""
import os
import subprocess


def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=5).decode('utf-8', errors='replace').strip()
    except Exception:
        return '(unavailable)'


def main():
    print('$ whoami')
    print(run('whoami'))
    print()

    print('$ id')
    print(run('id'))
    print()

    # Process tree from procfs
    print('$ # process tree (from /proc)')
    print(f'  {"PID":<6} {"PPID":<6} CMD')
    for entry in sorted(os.listdir('/proc')):
        if not entry.isdigit():
            continue
        pid = entry
        try:
            status = open(f'/proc/{pid}/status').read()
            ppid = ''
            for line in status.splitlines():
                if line.startswith('PPid:'):
                    ppid = line.split()[1]
                    break
            cmdline = open(f'/proc/{pid}/cmdline', 'rb').read()
            cmd = cmdline.replace(b'\x00', b' ').decode('utf-8', errors='replace').strip()
            # Shorten ld-linux wrapper: show just the actual program being run
            if 'ld-linux' in cmd and '/python3' in cmd:
                # Extract from python3 onward
                py_idx = cmd.find('/python3')
                cmd = '...' + cmd[py_idx:]
            cmd = cmd[:100]
            if not cmd:
                name = ''
                for line in status.splitlines():
                    if line.startswith('Name:'):
                        name = '[' + line.split()[1] + ']'
                        break
                cmd = name
            print(f'  {pid:<6} {ppid:<6} {cmd}')
        except Exception:
            continue
    print()

    print('$ cat /proc/1/cmdline')
    try:
        cmdline = open('/proc/1/cmdline', 'rb').read().replace(b'\x00', b' ').decode('utf-8', errors='replace').strip()
        print(f'  {cmdline}')
    except Exception as e:
        print(f'  (error: {e})')
    print()

    print('$ cat /proc/1/status | grep ...')
    try:
        status = open('/proc/1/status').read()
        for line in status.splitlines():
            if line.startswith(('Name:', 'Uid:', 'TracerPid:', 'CapBnd:', 'NoNewPrivs:', 'Seccomp:')):
                print(f'  {line}')
    except Exception as e:
        print(f'  (error: {e})')
    print()

    print('$ os.access("/proc/1/mem", R_OK | W_OK)')
    print(f'  readable: {os.access("/proc/1/mem", os.R_OK)}')
    print(f'  writable: {os.access("/proc/1/mem", os.W_OK)}')


if __name__ == '__main__':
    main()
