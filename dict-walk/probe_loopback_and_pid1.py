"""
probe_loopback_and_pid1.py — Stage 1.5 of 11-3-loopy-process-recon.

Two complementary probes on the AgentCore Harness microVM, both read-only:

(A) Loopback-port characterization. Curl the FastAPI / openapi shapes of
    every listening port we observed in Stage 1 (:48620, :8080, :1514,
    :1144, :37185, :53). Compares to the CodeInterpreter Kepler shape per
    [[agentcore-codeinterpreter-architecture]].

(B) PID-1 deep introspection. Full environ dump (no credential filter; we
    saw the filter cut interesting context in Stage 1), /proc/1/cmdline
    (re-confirm), /proc/1/cgroup, /proc/1/mountinfo (look for
    /mnt/agentcoresessionstorage, /run/secrets), /proc/1/limits,
    /proc/1/status (Cap*, NoNewPrivs, NSpid, namespace IDs), and /proc/1/maps
    summary (count + first 50 lines).

Authorized research; account owner is the test target.

Output format: line-delimited markers, ASCII-clean. Laptop side parses by
prefix.

Markers:
  PROBE=loopback-and-pid1 v1
  PORT=<port> RC=<curl-return-code> SIZE=<bytes>
  PORT_OPENAPI=<port>:<base64-of-first-3000-bytes-of-openapi-json>
  PORT_ROOT=<port>:<base64-of-first-1500-bytes-of-GET-/-response>
  PID1_FULL_ENV=<base64-of-environ-with-NUL-replaced-by-newline>
  PID1_CMDLINE=<base64-of-cmdline-with-NUL-replaced-by-space>
  PID1_CGROUP=<base64-of-/proc/1/cgroup>
  PID1_MOUNTINFO=<base64-of-/proc/1/mountinfo>
  PID1_LIMITS=<base64-of-/proc/1/limits>
  PID1_STATUS=<base64-of-/proc/1/status>
  PID1_MAPS_COUNT=<count>
  PID1_MAPS_HEAD=<base64-of-first-50-lines-of-/proc/1/maps>
  END
"""

import os
import sys
import base64
import subprocess


def _safe_read(path, max_bytes=128 * 1024):
    try:
        with open(path, 'rb') as f:
            return f.read(max_bytes)
    except Exception as e:
        return f'<read-error:{type(e).__name__}:{e}>'.encode()


def _b64(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.b64encode(data).decode()


def loopback_probe():
    ports = [48620, 8080, 1514, 1144, 37185, 53]
    for port in ports:
        # /openapi.json — the standard FastAPI advertise endpoint
        try:
            r = subprocess.run(
                ['curl', '-s', '-m', '4', '-o', '-',
                 f'http://127.0.0.1:{port}/openapi.json'],
                capture_output=True, timeout=8)
            print(f'PORT_OPENAPI={port}:RC{r.returncode}:'
                  f'{_b64(r.stdout[:3000])}')
        except Exception as e:
            print(f'PORT_OPENAPI={port}:EXC:{type(e).__name__}:{e}')

        # GET / — sometimes the server advertises a banner
        try:
            r = subprocess.run(
                ['curl', '-s', '-i', '-m', '4', f'http://127.0.0.1:{port}/'],
                capture_output=True, timeout=8)
            print(f'PORT_ROOT={port}:RC{r.returncode}:'
                  f'{_b64(r.stdout[:1500])}')
        except Exception as e:
            print(f'PORT_ROOT={port}:EXC:{type(e).__name__}:{e}')

        # docs page — FastAPI advertises a Swagger UI page that often leaks
        # the title even when openapi.json is gated.
        try:
            r = subprocess.run(
                ['curl', '-s', '-m', '4', '-o', '-',
                 f'http://127.0.0.1:{port}/docs'],
                capture_output=True, timeout=8)
            print(f'PORT_DOCS={port}:RC{r.returncode}:'
                  f'{_b64(r.stdout[:1500])}')
        except Exception as e:
            print(f'PORT_DOCS={port}:EXC:{type(e).__name__}:{e}')


def pid1_probe():
    environ = _safe_read('/proc/1/environ')
    if isinstance(environ, bytes) and not environ.startswith(b'<read-error'):
        # Replace NUL with newline for human readability post-base64.
        environ = environ.replace(b'\x00', b'\n')
    print(f'PID1_FULL_ENV={_b64(environ)}')

    cmdline = _safe_read('/proc/1/cmdline')
    if isinstance(cmdline, bytes) and not cmdline.startswith(b'<read-error'):
        cmdline = cmdline.replace(b'\x00', b' ')
    print(f'PID1_CMDLINE={_b64(cmdline)}')

    for fname, marker in [
        ('/proc/1/cgroup', 'PID1_CGROUP'),
        ('/proc/1/mountinfo', 'PID1_MOUNTINFO'),
        ('/proc/1/limits', 'PID1_LIMITS'),
        ('/proc/1/status', 'PID1_STATUS'),
    ]:
        data = _safe_read(fname)
        # mountinfo can be huge; cap at 32KB
        if len(data) > 32 * 1024:
            data = data[:32 * 1024]
        print(f'{marker}={_b64(data)}')

    # /proc/1/maps — count entries, capture first 50 lines, plus any line
    # with an interesting filename (not anon, not stack, not heap).
    maps_data = _safe_read('/proc/1/maps')
    if isinstance(maps_data, bytes) and not maps_data.startswith(b'<read-error'):
        lines = maps_data.split(b'\n')
        print(f'PID1_MAPS_COUNT={len(lines)}')
        head = b'\n'.join(lines[:50])
        print(f'PID1_MAPS_HEAD={_b64(head)}')
        # Filter for interesting filenames (anything not [heap]/[stack]/anon)
        interesting = [
            line for line in lines
            if line and b' ' in line and not line.endswith(b'[heap]')
            and not line.endswith(b'[stack]') and not line.endswith(b'[anon]')
        ]
        # Distinct filenames
        seen = set()
        distinct_files = []
        for line in interesting:
            parts = line.rsplit(b' ', 1)
            if len(parts) == 2 and parts[1].startswith(b'/'):
                fname = parts[1].decode('utf-8', errors='replace')
                if fname not in seen:
                    seen.add(fname)
                    distinct_files.append(fname)
        print(f'PID1_MAPS_DISTINCT_FILES_COUNT={len(distinct_files)}')
        # head of distinct files (first 100)
        head_files = '\n'.join(distinct_files[:100])
        print(f'PID1_MAPS_DISTINCT_FILES_HEAD={_b64(head_files)}')
    else:
        print(f'PID1_MAPS_ERR={_b64(maps_data)}')


def main():
    print('PROBE=loopback-and-pid1 v1')
    print('--- loopback ---')
    loopback_probe()
    print('--- pid1 ---')
    pid1_probe()
    print('END')


if __name__ == '__main__':
    main()
