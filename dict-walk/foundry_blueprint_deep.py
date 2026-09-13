#!/usr/bin/env python3
"""Deep probe of the blueprint MI: what app is fb60f99c, where does it live?"""
import json, base64, os, urllib.request, urllib.parse

ep = os.environ["IDENTITY_ENDPOINT"]
hdr = os.environ["IDENTITY_HEADER"]
bp = os.environ["FOUNDRY_AGENT_BLUEPRINT_CLIENT_ID"]
inst = os.environ["FOUNDRY_AGENT_INSTANCE_CLIENT_ID"]
proj_ep = os.environ.get("FOUNDRY_PROJECT_ENDPOINT", "")
tid = os.environ.get("FOUNDRY_AGENT_TENANT_ID", "")
pad = lambda s: s + "=" * (-len(s) % 4)

AUD = "fb60f99c-7a34-4190-8149-302f77469936"


def get_token(resource, client_id=None):
    url = f"{ep}?api-version=2019-08-01&resource={resource}"
    if client_id:
        url += f"&client_id={client_id}"
    req = urllib.request.Request(url, headers={"X-IDENTITY-HEADER": hdr})
    with urllib.request.urlopen(req) as r:
        return json.load(r)["access_token"]


def try_url(url, token, method="GET"):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"}, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read().decode()[:500]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:500]
    except Exception as e:
        return 0, str(e)[:200]


print("=" * 60)
print("BLUEPRINT MI DEEP PROBE")
print("=" * 60)

# 1. Graph: look up the audience app via the instance MI
print("\n=== 1. GRAPH: LOOK UP AUDIENCE APP ===")
try:
    graph_tok = get_token("https://graph.microsoft.com/", inst)
    # Use URL-encoded filter
    filt = urllib.parse.quote(f"appId eq '{AUD}'")
    code, body = try_url(f"https://graph.microsoft.com/v1.0/servicePrincipals?$filter={filt}", graph_tok)
    print(f"  servicePrincipals (filter appId={AUD}): HTTP {code}")
    print(f"  {body[:300]}")
    print()
    # Also try direct by appId
    code2, body2 = try_url(f"https://graph.microsoft.com/v1.0/servicePrincipals(appId='{AUD}')", graph_tok)
    print(f"  servicePrincipals(appId='{AUD}'): HTTP {code2}")
    print(f"  {body2[:300]}")
except Exception as e:
    print(f"  Graph error: {e}")

# 2. Try the audience app as a resource directly (maybe it's a self-service URL)
print("\n=== 2. REQUEST TOKEN FOR THE AUDIENCE AS RESOURCE ===")
for cid_label, cid in [("instance", inst), ("blueprint", bp)]:
    try:
        tok = get_token(f"api://{AUD}", cid)
        claims = json.loads(base64.urlsafe_b64decode(pad(tok.split(".")[1])))
        print(f"  {cid_label} -> api://{AUD}: aud={claims.get('aud')} WORKED!")
    except Exception as e:
        print(f"  {cid_label} -> api://{AUD}: {str(e)[:150]}")

# 3. Decode xms_ftd (federated token details) - might contain endpoint info
print("\n=== 3. DECODE xms_ftd ===")
bp_tok = get_token("https://ai.azure.com/", bp)
claims = json.loads(base64.urlsafe_b64decode(pad(bp_tok.split(".")[1])))
ftd = claims.get("xms_ftd", "")
print(f"  raw: {ftd}")
try:
    decoded = base64.urlsafe_b64decode(pad(ftd))
    print(f"  decoded bytes: {decoded}")
    print(f"  decoded str: {decoded.decode('utf-8', errors='replace')}")
except Exception as e:
    print(f"  decode error: {e}")

ficinfo = claims.get("xms_ficinfo", "")
print(f"\n  xms_ficinfo raw: {ficinfo}")
try:
    decoded = base64.urlsafe_b64decode(pad(ficinfo))
    print(f"  decoded: {decoded.hex()}")
except Exception:
    pass

idrel = claims.get("xms_idrel", "")
print(f"  xms_idrel: {idrel}")

# 4. Try Foundry-internal URLs with the blueprint token
print("\n=== 4. FOUNDRY INTERNAL URLS WITH BLUEPRINT TOKEN ===")
# The xms_ftd contained "europesnorth-dsms" -- try that region's endpoints
internal_urls = [
    f"https://agents.eastus2.hyena.infra.ai.azure.com/",
    f"https://agents.eastus2.hyena.infra.ai.azure.com/agents/v2.0/subscriptions",
    f"https://eastus2.agents.azure.com/",
    f"https://eastus2.api.azureml.ms/",
    f"https://niv-foundry-research-eus2.cognitiveservices.azure.com/",
    f"https://niv-foundry-research-eus2.openai.azure.com/",
    f"https://niv-foundry-research-eus2.services.ai.azure.com/",
    f"https://niv-foundry-research-eus2.services.ai.azure.com/api/projects/proj-default/agents",
]
for url in internal_urls:
    code, body = try_url(url, bp_tok)
    if code != 0:
        print(f"  {url}: HTTP {code}")
        if code not in (404, 000) and len(body) > 10:
            print(f"    {body[:150]}")

# 5. Try the same URLs with the instance token for comparison
print("\n=== 5. SAME URLS WITH INSTANCE TOKEN (CogSvc audience) ===")
inst_tok = get_token("https://cognitiveservices.azure.com/", inst)
for url in internal_urls[-3:]:
    code, body = try_url(url, inst_tok)
    if code != 0:
        print(f"  {url}: HTTP {code}")
        if code not in (404, 000) and len(body) > 10:
            print(f"    {body[:150]}")

# 6. Check if the blueprint can access MCP/toolset
print("\n=== 6. TOOLSET / MCP ENDPOINTS ===")
toolset = os.environ.get("FOUNDRY_AGENT_TOOLSET_ENDPOINT", "")
print(f"  FOUNDRY_AGENT_TOOLSET_ENDPOINT = '{toolset}'")
if toolset:
    for tok_label, tok in [("blueprint", bp_tok), ("instance", inst_tok)]:
        code, body = try_url(toolset, tok if tok_label == "blueprint" else inst_tok)
        print(f"  {tok_label}: HTTP {code} -> {body[:150]}")

print("\nDONE")
