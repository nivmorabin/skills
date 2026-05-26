"""Probe2d shell-tool payload — runs INSIDE the harness with the scoped exec role.

Tests each of the four cells of the mitigation matrix from the harness's
actual exec context (i.e., what an attacker reaching the shell tool via
ingested-content would actually have available):

  1. CreateEvent(actor=alice)  control            — should be ALLOWED
  2. CreateEvent(actor=bob)    cross-actor forge  — expected DENIED if
                                                    actorId condition works
  3. BatchCreateMemoryRecords(namespace=shared)   — expected ALLOWED
                                                    (action not in gated list)
  4. UpdateMemory(addCustomStrategy)              — expected ALLOWED
                                                    (control plane)

Env vars: FORGE_MEMORY_ID, FORGE_ALICE_ACTOR, FORGE_BOB_ACTOR,
          FORGE_STRATEGY_ID, FORGE_NAMESPACE, FORGE_CANARY
"""

import json
import os
import uuid
from datetime import datetime, timezone

import boto3


def main():
    region = os.environ.get("AWS_REGION", "us-east-1")
    memory_id = os.environ.get("FORGE_MEMORY_ID")
    alice_actor = os.environ.get("FORGE_ALICE_ACTOR")
    bob_actor = os.environ.get("FORGE_BOB_ACTOR")
    strategy_id = os.environ.get("FORGE_STRATEGY_ID")
    namespace = os.environ.get("FORGE_NAMESPACE", "support/global")
    canary = os.environ.get("FORGE_CANARY", "p2d")
    if not (memory_id and alice_actor and bob_actor):
        print("PROBE_VERDICT=MISSING_ENV")
        return

    bac = boto3.client("bedrock-agentcore", region_name=region)
    bacc = boto3.client("bedrock-agentcore-control", region_name=region)
    sts = boto3.client("sts", region_name=region)
    print(f"PROBE_CALLER={sts.get_caller_identity().get('Arn')}")

    # 1. CreateEvent(actor=alice) — control
    try:
        sess_id = f"acab-p2d-A-{uuid.uuid4().hex[:12]}{uuid.uuid4().hex[:25]}"
        r = bac.create_event(
            memoryId=memory_id, actorId=alice_actor, sessionId=sess_id,
            eventTimestamp=datetime.now(timezone.utc),
            payload=[{"conversational": {"content": {"text": f"P2D control {canary}"}, "role": "USER"}}],
        )
        print(f"PROBE_1_CREATEEVENT_ALICE=ALLOWED ev={(r.get('event') or {}).get('eventId')}")
    except Exception as e:
        code = getattr(e, "response", {}).get("Error", {}).get("Code", type(e).__name__)
        print(f"PROBE_1_CREATEEVENT_ALICE=DENIED({code}): {str(e)[:160]}")

    # 2. CreateEvent(actor=bob) — cross-actor forgery; should be DENIED
    try:
        sess_id = f"acab-p2d-B-{uuid.uuid4().hex[:12]}{uuid.uuid4().hex[:25]}"
        r = bac.create_event(
            memoryId=memory_id, actorId=bob_actor, sessionId=sess_id,
            eventTimestamp=datetime.now(timezone.utc),
            payload=[{"conversational": {"content": {"text": f"P2D forgery {canary}"}, "role": "USER"}}],
        )
        print(f"PROBE_2_CREATEEVENT_BOB=ALLOWED ev={(r.get('event') or {}).get('eventId')}")
    except Exception as e:
        code = getattr(e, "response", {}).get("Error", {}).get("Code", type(e).__name__)
        print(f"PROBE_2_CREATEEVENT_BOB=DENIED({code}): {str(e)[:160]}")

    # 3. BatchCreateMemoryRecords — namespace-scoped, NOT actor-scoped
    if strategy_id:
        try:
            r = bac.batch_create_memory_records(
                memoryId=memory_id,
                records=[{
                    "requestIdentifier": uuid.uuid4().hex,
                    "namespaces": [namespace],
                    "content": {"text": f"P2D batch test {canary}"},
                    "timestamp": datetime.now(timezone.utc),
                    "memoryStrategyId": strategy_id,
                }],
            )
            ok = len(r.get("successfulRecords", []))
            failed = len(r.get("failedRecords", []))
            verdict = "ALLOWED" if ok else "PARTIAL"
            print(f"PROBE_3_BATCHCREATE=({verdict}) ok={ok} failed={failed}")
        except Exception as e:
            code = getattr(e, "response", {}).get("Error", {}).get("Code", type(e).__name__)
            print(f"PROBE_3_BATCHCREATE=DENIED({code}): {str(e)[:160]}")
    else:
        print("PROBE_3_BATCHCREATE=SKIP_NO_STRATEGY")

    # 4. UpdateMemory addCustomStrategy with appendToPrompt — control plane
    new_name = f"p2d_test_{uuid.uuid4().hex[:6]}"
    try:
        r = bacc.update_memory(
            memoryId=memory_id,
            memoryStrategies={
                "addMemoryStrategies": [{
                    "customMemoryStrategy": {
                        "name": new_name,
                        "description": "Probe2d harness-side strategy add",
                        "namespaces": [f"p2d/test/{canary}"],
                        "configuration": {
                            "semanticOverride": {
                                "extraction": {
                                    "appendToPrompt": f"P2D harness-side {canary}",
                                    "modelId": "us.amazon.nova-pro-v1:0",
                                },
                            },
                        },
                    },
                }],
            },
        )
        print(f"PROBE_4_UPDATEMEMORY_ADDSTRATEGY=ALLOWED new_name={new_name}")
    except Exception as e:
        code = getattr(e, "response", {}).get("Error", {}).get("Code", type(e).__name__)
        print(f"PROBE_4_UPDATEMEMORY_ADDSTRATEGY=DENIED({code}): {str(e)[:160]}")

    print("PROBE_VERDICT=DONE")


if __name__ == "__main__":
    main()
