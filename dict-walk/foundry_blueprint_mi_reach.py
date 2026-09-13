#!/usr/bin/env python3
"""Probe what the BLUEPRINT MI can access vs the instance MI.

The blueprint MI (client_id from FOUNDRY_AGENT_BLUEPRINT_CLIENT_ID) returns a
federated-identity JWT with a structured sub claim and no appid. This script
tests what it can reach that the instance MI cannot.
"""
import json, base64, os, urllib.request, sys

ep = os.environ["IDENTITY_ENDPOINT"]
hdr = os.environ["IDENTITY_HEADER"]
instance_cid = os.environ.get("FOUNDRY_AGENT_INSTANCE_CLIENT_ID", "")
blueprint_cid = os.environ.get("FOUNDRY_AGENT_BLUEPRINT_CLIENT_ID", "")
project_ep = os.environ.get("FOUNDRY_PROJECT_ENDPOINT", "")
project_arm = os.environ.get("FOUNDRY_PROJECT_ARM_ID", "")
toolset_ep = os.environ.get("FOUNDRY_AGENT_TOOLSET_ENDPOINT", "")

pad = lambda s: s + "=" * (-len(s) % 4)


def get_token(resource, client_id=None):
    url = f"{ep}?api-version=2019-08-01&resource={resource}"
    if client_id:
        url += f"&client_id={client_id}"
    req = urllib.request.Request(url, headers={"X-IDENTITY-HEADER": hdr})
    with urllib.request.urlopen(req) as r:
        return json.load(r)["access_token"]


def api_call(url, token, method="GET"):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"}, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:300]
        return e.code, body


def decode_jwt(tok):
    parts = tok.split(".")
    return json.loads(base64.urlsafe_b64decode(pad(parts[1])))


print("=" * 60)
print("BLUEPRINT MI vs INSTANCE MI REACH TEST")
print("=" * 60)
print(f"instance: {instance_cid}")
print(f"blueprint: {blueprint_cid}")
print(f"project: {project_ep}")
print(f"toolset: {toolset_ep or '(empty)'}")
print()

# Get both tokens for each interesting audience
audiences = [
    ("https://management.azure.com/", "ARM"),
    ("https://cognitiveservices.azure.com/", "CogSvc"),
    ("https://ai.azure.com/", "AI"),
    ("https://graph.microsoft.com/", "Graph"),
]

tokens = {}
for resource, label in audiences:
    print(f"--- {label} ({resource}) ---")
    for name, cid in [("instance", instance_cid), ("blueprint", blueprint_cid)]:
        try:
            tok = get_token(resource, cid)
            claims = decode_jwt(tok)
            tokens[(label, name)] = tok
            print(f"  {name}: appid={claims.get('appid')} oid={claims.get('oid','')[:20]}... roles={claims.get('roles',[])} scp={claims.get('scp','')}")
        except Exception as e:
            print(f"  {name}: FAILED ({e})")
    print()

# Now test what each can do
print("=" * 60)
print("REACH COMPARISON")
print("=" * 60)

# 1. ARM: subscriptions
print("\n1. ARM /subscriptions")
for name in ["instance", "blueprint"]:
    tok = tokens.get(("ARM", name))
    if not tok:
        print(f"  {name}: no token"); continue
    code, data = api_call("https://management.azure.com/subscriptions?api-version=2022-12-01", tok)
    count = len(data.get("value", [])) if isinstance(data, dict) else "err"
    print(f"  {name}: HTTP {code}, subscriptions={count}")

# 2. ARM: read the Foundry project
print("\n2. ARM: read Foundry project")
for name in ["instance", "blueprint"]:
    tok = tokens.get(("ARM", name))
    if not tok:
        print(f"  {name}: no token"); continue
    code, data = api_call(f"https://management.azure.com{project_arm}?api-version=2024-10-01", tok)
    print(f"  {name}: HTTP {code}, {str(data)[:150]}")

# 3. CogSvc: list models / call the model endpoint
print("\n3. CogSvc: model access")
cogsvc_base = project_ep.replace("/api/projects/proj-default", "")
for name in ["instance", "blueprint"]:
    tok = tokens.get(("CogSvc", name))
    if not tok:
        print(f"  {name}: no token"); continue
    # Try listing models
    code, data = api_call(f"{cogsvc_base}/openai/models?api-version=2024-10-21", tok)
    print(f"  {name} (list models): HTTP {code}, {str(data)[:150]}")
    # Try a simple completion
    code2, data2 = api_call(f"{cogsvc_base}/openai/deployments/gpt-5.4/chat/completions?api-version=2024-10-21", tok)
    print(f"  {name} (completions): HTTP {code2}")

# 4. Foundry data plane: agents API
print("\n4. Foundry agents API")
for name in ["instance", "blueprint"]:
    tok = tokens.get(("AI", name))
    if not tok:
        print(f"  {name}: no token"); continue
    # List agents
    code, data = api_call(f"{project_ep}/agents?api-version=2025-05-15-preview", tok)
    print(f"  {name} (list agents): HTTP {code}, {str(data)[:200]}")

# 5. Foundry data plane: connections (might have secrets)
print("\n5. Foundry connections")
for name in ["instance", "blueprint"]:
    tok = tokens.get(("AI", name))
    if not tok:
        print(f"  {name}: no token"); continue
    code, data = api_call(f"{project_ep}/connections?api-version=2025-05-15-preview", tok)
    print(f"  {name} (connections): HTTP {code}, {str(data)[:200]}")

# 6. Toolset endpoint (if set)
if toolset_ep:
    print(f"\n6. Toolset endpoint ({toolset_ep})")
    for name in ["instance", "blueprint"]:
        tok = tokens.get(("AI", name))
        if not tok:
            print(f"  {name}: no token"); continue
        code, data = api_call(f"{toolset_ep}", tok)
        print(f"  {name}: HTTP {code}, {str(data)[:150]}")

# 7. Decode the blueprint JWT sub claim
print("\n" + "=" * 60)
print("BLUEPRINT JWT ANALYSIS")
print("=" * 60)
for label, _ in audiences:
    tok = tokens.get((label, "blueprint"))
    if not tok:
        continue
    claims = decode_jwt(tok)
    print(f"\n{label}:")
    print(f"  full sub: {claims.get('sub')}")
    # Try to decode the base64 parts of the sub
    sub = claims.get("sub", "")
    parts = sub.split("/")
    for i, p in enumerate(parts):
        if len(p) > 10:
            try:
                decoded = base64.urlsafe_b64decode(pad(p))
                print(f"  sub[{i}] decoded: {decoded}")
            except Exception:
                print(f"  sub[{i}] raw: {p}")
    break  # same sub across audiences

print("\nDONE")
