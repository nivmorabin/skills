"""Blog demo — reverse the vault credential resolution mechanism.

Reads the actual source code from inside the harness runtime to show
HOW the ${arn:...} reference gets resolved into a Bearer token that
lands in PID 1's heap.

The data flow we're tracing:
  1. Harness config has: Authorization: Bearer ${arn:aws:bedrock-agentcore:...:token-vault/...}
  2. loopy/tools/__init__.py:resolve_header_references() sees the ${arn:...} pattern
  3. It calls get_workload_access_token() or reads AWS_WORKLOAD_ACCESS_TOKEN
  4. Then calls get_resource_api_key(workloadIdentityToken=..., resourceCredentialProviderName=...)
  5. The returned API key (= the vault-stored credential) replaces the ${arn:...} in the header
  6. httpx sends the resolved Bearer to the MCP server
  7. The credential bytes are now in PID 1's heap — in httpx buffers, Python dicts, and the response cache

This script reads the source files and prints the relevant functions,
so the blog reader can see exactly how the mechanism works.

Hosted at github.com/nivmorabin/skills/dict-walk/pid1_vault_mechanism.py
"""
import os
import re
import sys


def section(title):
    print(f'\n{"=" * 60}')
    print(f'  {title}')
    print(f'{"=" * 60}')


def read_file(path):
    try:
        return open(path).read()
    except Exception as e:
        return f'(error: {e})'


def extract_function(source, func_name, context_lines=3):
    """Extract a function definition from source, including its body."""
    lines = source.split('\n')
    start = None
    for i, line in enumerate(lines):
        if f'def {func_name}' in line:
            start = max(0, i - context_lines)
            break
    if start is None:
        return None

    # Find the end of the function (next def at same or lower indent, or end of file)
    func_indent = len(lines[start + context_lines]) - len(lines[start + context_lines].lstrip())
    end = len(lines)
    for i in range(start + context_lines + 1, len(lines)):
        stripped = lines[i]
        if stripped.strip() and not stripped.startswith(' ' * (func_indent + 1)):
            if stripped.strip().startswith('def ') or stripped.strip().startswith('class '):
                end = i
                break
    return '\n'.join(lines[start:end])


def extract_class(source, class_name, max_lines=60):
    """Extract a class definition (first max_lines lines)."""
    lines = source.split('\n')
    start = None
    for i, line in enumerate(lines):
        if f'class {class_name}' in line:
            start = i
            break
    if start is None:
        return None
    end = min(start + max_lines, len(lines))
    for i in range(start + 1, len(lines)):
        if i > start + 5 and lines[i].strip() and not lines[i].startswith(' '):
            end = i
            break
    return '\n'.join(lines[start:min(end, start + max_lines)])


PKG = '/opt/amazon/lib/python3.10/site-packages'


def main():
    section('VAULT CREDENTIAL RESOLUTION — SOURCE CODE TRACE')
    print('  Reading the harness source to understand how ${arn:...}')
    print('  vault references are resolved into Bearer tokens at runtime.')
    print()
    print('  Data flow:')
    print('    config: Authorization: Bearer ${arn:...:token-vault/.../...}')
    print('       ↓')
    print('    loopy/tools/__init__.py: resolve_header_references()')
    print('       ↓')
    print('    bedrock-agentcore Identity API: GetResourceApiKey')
    print('       ↓')
    print('    Resolved Bearer token lands in PID 1 heap (httpx buffers)')

    # --- 1. loopy/tools/__init__.py — the resolution function ---
    section('1. loopy/tools/__init__.py (vault resolution)')
    tools_init = read_file(f'{PKG}/loopy/tools/__init__.py')
    if 'error' in tools_init[:20]:
        print(f'  {tools_init}')
    else:
        # Try multiple function names for the resolver
        found_fn = None
        for fn_name in ('resolve_header_references', 'resolve_headers', '_resolve_header',
                        'resolve_arn', '_resolve_arn_references', 'resolve_credentials'):
            found_fn = extract_function(tools_init, fn_name)
            if found_fn:
                print(f'  # Found: {fn_name}()')
                print(found_fn)
                break
        if not found_fn:
            # Search for ${arn: or token-vault or credential-provider patterns
            lines = tools_init.split('\n')
            relevant = []
            seen = set()
            for i, line in enumerate(lines):
                if any(kw in line for kw in ('${', 'arn:', 'resolve', 'header_ref',
                                              'credential', 'api_key', 'bearer',
                                              'token_vault', 'token-vault', 'GetResource')):
                    start = max(0, i - 2)
                    end = min(len(lines), i + 8)
                    for j in range(start, end):
                        if j not in seen:
                            relevant.append(lines[j])
                            seen.add(j)
                    relevant.append('  ...')
            if relevant:
                print('  # Relevant fragments (resolve_header_references not found as standalone):')
                print('\n'.join(relevant[:100]))
            else:
                # Show the whole file (it's probably the key file)
                print(f'  # Full file ({len(tools_init)} bytes):')
                print(tools_init[:4000])

    # --- 2. bedrock_agentcore/identity/ — the Identity SDK ---
    section('2. bedrock_agentcore/identity/auth.py')
    auth_src = read_file(f'{PKG}/bedrock_agentcore/identity/auth.py')
    if 'error' in auth_src[:20]:
        print(f'  {auth_src}')
    else:
        # Show the decorators / key functions
        for func_name in ('requires_api_key', 'requires_access_token', '_get_api_key', '_resolve'):
            fn = extract_function(auth_src, func_name)
            if fn:
                print(fn)
                print()
        if not any(extract_function(auth_src, f) for f in ('requires_api_key', 'requires_access_token', '_get_api_key', '_resolve')):
            # Just show the file
            print(auth_src[:3000])

    # --- 3. bedrock_agentcore/identity/__init__.py ---
    section('3. bedrock_agentcore/identity/__init__.py')
    identity_init = read_file(f'{PKG}/bedrock_agentcore/identity/__init__.py')
    if 'error' in identity_init[:20]:
        print(f'  {identity_init}')
    else:
        print(identity_init[:2000])

    # --- 4. bedrock_agentcore/services/identity.py — the client ---
    section('4. bedrock_agentcore/services/identity.py (API client)')
    identity_svc = read_file(f'{PKG}/bedrock_agentcore/services/identity.py')
    if 'error' in identity_svc[:20]:
        print(f'  {identity_svc}')
    else:
        # Show get_resource_api_key or get_workload_access_token
        for func_name in ('get_resource_api_key', 'get_workload_access_token', 'get_api_key', 'resolve'):
            fn = extract_function(identity_svc, func_name)
            if fn:
                print(fn)
                print()
        if not any(extract_function(identity_svc, f) for f in ('get_resource_api_key', 'get_workload_access_token')):
            print(identity_svc[:3000])

    # --- 5. loopy/config.py — where the ${arn:...} is parsed from config ---
    section('5. loopy/config.py (harness configuration)')
    config_src = read_file(f'{PKG}/loopy/config.py')
    if 'error' in config_src[:20]:
        print(f'  {config_src}')
    else:
        # Show relevant parts
        lines = config_src.split('\n')
        relevant = []
        for i, line in enumerate(lines):
            if any(kw in line.lower() for kw in ('remote_mcp', 'header', 'credential', 'arn', 'bearer', 'authorization')):
                start = max(0, i - 1)
                end = min(len(lines), i + 3)
                for l in lines[start:end]:
                    if l not in relevant:
                        relevant.append(l)
        if relevant:
            print('\n'.join(relevant[:60]))
        else:
            print(config_src[:2000])

    # --- Summary ---
    section('MECHANISM SUMMARY')
    print('  The resolution path we just traced:')
    print()
    print('  1. Customer creates harness with:')
    print('       Authorization: Bearer ${arn:...:token-vault/.../apikeycredentialprovider/...}')
    print()
    print('  2. At invoke time, loopy/tools/__init__.py calls resolve_header_references()')
    print('     which detects the ${arn:...} pattern in the MCP tool headers.')
    print()
    print('  3. It extracts the credential provider name from the ARN and calls:')
    print('       get_workload_access_token() → workload token')
    print('       get_resource_api_key(token, provider_name) → the actual secret')
    print()
    print('  4. The resolved secret replaces ${arn:...} in the Authorization header.')
    print('     httpx sends it to the MCP server. The bytes now live in PID 1 heap:')
    print('       - httpx request buffer (outbound)')
    print('       - Python dict cache (resolve_header_references return value)')
    print('       - Possibly httpx connection pool (kept alive for reuse)')
    print()
    print('  5. The shell tool reads /proc/1/mem → finds the resolved Bearer → exfils.')
    print()
    print('  The vault provides at-rest and in-transit protection.')
    print('  It provides ZERO in-use protection. The credential lives in')
    print('  the same address space as the shell tool\'s code execution.')

    section('DONE')


if __name__ == '__main__':
    main()
