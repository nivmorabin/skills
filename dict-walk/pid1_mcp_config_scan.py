"""Notebook-15 §4 — remote_mcp config residency scan in PID 1.

Sweeps PID 1's writable-private anonymous heap for every byte-anchored
fragment of the harness's remote_mcp tool configurations:

  - Each tool's URL (full and host substring)
  - Each tool's prefix/name
  - Each tool's planted markers (X-Vault-Canary, X-Decoy-Marker)
  - Authorization header values (full bearer prefix)
  - The 'remote_mcp' type literal and HarnessRemoteMcpConfig pydantic class names
  - MCPClient instance markers (Strands prefix anchors)

For each match, prints VA, region size, occurrence count, and a 64-byte
context window so the notebook can tell whether the bytes live in:
  - a Python str/bytes object (rich pointer-shaped neighbors)
  - an httpx request/response buffer (HTTP framing visible)
  - a Strands AgentTool catalog dict (tool spec JSON neighbors)

Configuration via environment variables (set inline by the calling
shell command):

  NB15_TOOLS — comma-separated tool descriptors. Each descriptor is
    pipe-separated as: "prefix|url|marker_header|marker_value".
    Example:
      vault-probe-mcp|https://...legit.../invocations|X-Vault-Canary|IDENT-APIKEY-CANARY...
      decoy-mcp|https://...decoy.../invocations|X-Decoy-Marker|NB15-DECOY-LIVE

Hosted at github.com/nivmorabin/skills/dict-walk/pid1_mcp_config_scan.py.
"""
import os
import re
import sys


def _parse_tools_env():
    raw = os.environ.get('NB15_TOOLS', '')
    if not raw:
        return []
    out = []
    for desc in raw.split(','):
        desc = desc.strip()
        if not desc:
            continue
        parts = desc.split('|')
        if len(parts) != 4:
            print(f'BAD_TOOL_DESC={desc!r}')
            continue
        out.append({
            'prefix': parts[0],
            'url': parts[1],
            'marker_header': parts[2],
            'marker_value': parts[3],
        })
    return out


def _enumerate_writable_anon_regions():
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
    return regions


def _scan_for_anchor(mem_handle, regions, anchor_bytes):
    """Yield (va, region_size, offset, context_window) per occurrence."""
    for start, end in regions:
        size = end - start
        try:
            mem_handle.seek(start)
            chunk = mem_handle.read(size)
        except Exception:
            continue
        if anchor_bytes not in chunk:
            continue
        idx = -1
        while True:
            idx = chunk.find(anchor_bytes, idx + 1)
            if idx < 0:
                break
            ws = max(0, idx - 32)
            we = min(len(chunk), idx + len(anchor_bytes) + 32)
            yield (start, size, idx, chunk[ws:we])


def main():
    tools = _parse_tools_env()
    if not tools:
        print('SCAN_FAIL=no_tools_configured')
        sys.exit(1)

    regions = _enumerate_writable_anon_regions()
    print(f'WRITABLE_PRIVATE_ANON_REGIONS={len(regions)}')

    # Generic anchors — applied to every tool, plus once per scan.
    generic_anchors = [
        ('TYPE_LITERAL', b'remote_mcp'),
        ('PYDANTIC_REMOTE_MCP_CONFIG', b'HarnessRemoteMcpConfig'),
        ('PYDANTIC_HEADERS', b'HarnessHeaders'),
        ('STRANDS_PREFIX', b'MCPClient'),
        ('STRANDS_AGENT_TOOL', b'AgentTool'),
        ('FASTMCP_SERVER', b'FastMCP'),
        ('MCP_INITIALIZE', b'"method":"initialize"'),
        ('MCP_TOOLS_LIST', b'"method":"tools/list"'),
    ]

    with open('/proc/1/mem', 'rb') as mem:
        # Generic anchors (not per-tool).
        print()
        print('=== GENERIC ANCHORS ===')
        for label, needle in generic_anchors:
            count = 0
            first_va = None
            first_ctx = None
            for va, _size, _off, ctx in _scan_for_anchor(mem, regions, needle):
                count += 1
                if first_va is None:
                    first_va = va
                    first_ctx = ctx
            print(f'{label}_OCCURRENCES={count}')
            if first_ctx:
                print(f'{label}_FIRST_VA={hex(first_va)}')
                print(f'{label}_FIRST_CONTEXT={first_ctx!r}')

        # Per-tool anchors.
        for i, t in enumerate(tools, start=1):
            print()
            print(f'=== TOOL[{i}] prefix={t["prefix"]} ===')

            # URL host substring (avoids hash-style padding noise from full URL).
            host_anchor = b''
            url = t['url']
            try:
                # Strip scheme + path; keep host:port.
                host = url.split('://', 1)[-1].split('/', 1)[0]
                host_anchor = host.encode('ascii')
            except Exception:
                pass

            anchors_per_tool = [
                ('FULL_URL', t['url'].encode('ascii')),
                ('URL_HOST', host_anchor),
                ('PREFIX', t['prefix'].encode('ascii')),
                ('MARKER_HEADER_NAME', t['marker_header'].encode('ascii')),
                ('MARKER_VALUE', t['marker_value'].encode('ascii')),
            ]
            for label, needle in anchors_per_tool:
                if not needle:
                    continue
                count = 0
                first_va = None
                first_ctx = None
                first_size = None
                for va, size, _off, ctx in _scan_for_anchor(mem, regions, needle):
                    count += 1
                    if first_va is None:
                        first_va = va
                        first_ctx = ctx
                        first_size = size
                print(f'TOOL[{i}]_{label}_OCCURRENCES={count}')
                if first_ctx:
                    print(f'TOOL[{i}]_{label}_FIRST_VA={hex(first_va)}')
                    print(f'TOOL[{i}]_{label}_FIRST_REGION_SIZE={first_size}')
                    print(f'TOOL[{i}]_{label}_FIRST_CONTEXT={first_ctx!r}')

    print()
    print('SCAN_VERDICT=COMPLETE')


if __name__ == '__main__':
    main()
