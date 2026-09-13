#!/usr/bin/env python3
"""Final blueprint MI probe: find the service behind fb60f99c."""
import json, base64, os, urllib.request, urllib.parse

ep = os.environ["IDENTITY_ENDPOINT"]
hdr = os.environ["IDENTITY_HEADER"]
bp = os.environ["FOUNDRY_AGENT_BLUEPRINT_CLIENT_ID"]
inst = os.environ["FOUNDRY_AGENT_INSTANCE_CLIENT_ID"]
proj = os.environ.get("FOUNDRY_PROJECT_ENDPOINT", "").rstrip("/")
agent_name = os.environ.get("FOUNDRY_AGENT_NAME", "")
agent_id = os.environ.get("FOUNDRY_AGENT_ID", "")
session_id = os.environ.get("FOUNDRY_AGENT_SESSION_ID", "")
tid = os.environ.get("FOUNDRY_AGENT_TENANT_ID", "")

AUD = "fb60f99c-7a34-4190-8149-302f77469936"
pad = lambda s: s + "=" * (-len(s) % 4)


def get_token(resource, client_id=None):
    url = f"{ep}?api-version=2019-08-01&resource={resource}"
    if client_id:
        url += f"&client_id={client_id}"
    req = urllib.request.Request(url, headers={"X-IDENTITY-HEADER": hdr})
    with urllib.request.urlopen(req) as r:
        return json.load(r)["access_token"]


def try_url(url, token, method="GET", data=None, ct=None):
    headers = {"Authorization": f"Bearer {token}"}
    if ct:
        headers["Content-Type"] = ct
    req = urllib.request.Request(url, headers=headers, method=method, data=data)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, dict(r.headers), r.read().decode()[:600]
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()[:600]
    except Exception as e:
        return 0, {}, str(e)[:200]


# Get both tokens
bp_tok = get_token("https://ai.azure.com/", bp)
inst_tok = get_token("https://ai.azure.com/", inst)

# Decode blueprint claims for context
claims = json.loads(base64.urlsafe_b64decode(pad(bp_tok.split(".")[1])))
print(f"blueprint aud: {claims.get('aud')}")
print(f"blueprint azp: {claims.get('azp')}")
print(f"agent: {agent_name} id={agent_id}")
print()

# 1. Hyena agents backend (seen in error messages)
print("=" * 50)
print("1. HYENA AGENTS BACKEND")
print("=" * 50)
hyena_bases = [
    "https://agents.eastus2.hyena.infra.ai.azure.com",
    "https://eastus2.agents.azure.com",
]
sub = proj.split("/subscriptions/")[1].split("/")[0] if "/subscriptions/" in proj else ""
rg = proj.split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in proj else ""
acct = proj.split("/accounts/")[1].split("/")[0] if "/accounts/" in proj else ""

for base in hyena_bases:
    for tok_label, tok in [("blueprint", bp_tok), ("instance", inst_tok)]:
        for path in [
            "/",
            f"/agents/v2.0/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.CognitiveServices/accounts/{acct}",
            f"/agents/v2.0/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.CognitiveServices/accounts/{acct}/agents",
            f"/agents/v2.0/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.CognitiveServices/accounts/{acct}/agents/{agent_name}",
        ]:
            code, hdrs, body = try_url(f"{base}{path}", tok)
            if code not in (0, 404):
                print(f"  {tok_label} {base}{path[-40:]}: HTTP {code}")
                if code not in (405,) and body:
                    print(f"    {body[:200]}")

# 2. Try the audience app ID as a resource directly (not api://)
print()
print("=" * 50)
print("2. TOKEN WITH AUDIENCE AS RESOURCE (various forms)")
print("=" * 50)
for resource in [
    f"https://{AUD}/",
    f"{AUD}/.default",
    "https://foundry.azure.com/",
    "https://agents.azure.com/",
    "https://agentservice.azure.com/",
    "https://hyena.azure.com/",
]:
    for cid_label, cid in [("blueprint", bp), ("instance", inst)]:
        try:
            tok = get_token(resource, cid)
            c = json.loads(base64.urlsafe_b64decode(pad(tok.split(".")[1])))
            print(f"  {cid_label} resource={resource}: aud={c.get('aud')} WORKED!")
        except Exception as e:
            err = str(e)[:80]
            if "400" not in err and "AADSTS" not in err:
                print(f"  {cid_label} resource={resource}: {err}")

# 3. Discovery endpoints for the audience app
print()
print("=" * 50)
print("3. APP DISCOVERY")
print("=" * 50)
disc_urls = [
    f"https://login.microsoftonline.com/{tid}/v2.0/.well-known/openid-configuration?appid={AUD}",
    f"https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration?appid={AUD}",
]
for url in disc_urls:
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            data = json.load(r)
            # Check if the token_endpoint or any field references the app
            print(f"  {url[-60:]}:")
            print(f"    issuer: {data.get('issuer')}")
    except Exception as e:
        print(f"  {url[-60:]}: {e}")

# 4. DNS discovery from the container
print()
print("=" * 50)
print("4. DNS DISCOVERY")
print("=" * 50)
import subprocess
for hostname in [
    "agents.eastus2.hyena.infra.ai.azure.com",
    "hyena-eastus2-01.eastus2.hyena.infra.ai.azure.com",
    f"{acct}.services.ai.azure.com",
    f"{acct}.cognitiveservices.azure.com",
    f"{acct}.openai.azure.com",
    "foundry.azure.com",
    "agentservice.azure.com",
]:
    try:
        r = subprocess.run(["getent", "hosts", hostname], capture_output=True, text=True, timeout=3)
        if r.returncode == 0 and r.stdout.strip():
            print(f"  {hostname}: {r.stdout.strip()}")
        else:
            # try with nslookup if getent fails
            r2 = subprocess.run(["nslookup", hostname], capture_output=True, text=True, timeout=3)
            for line in r2.stdout.split("\n"):
                if "Address" in line and "127" not in line and "168.63" not in line:
                    print(f"  {hostname}: {line.strip()}")
                    break
    except Exception:
        pass

# 5. The nuclear option: try the blueprint token against EVERY response header
# we've seen that mentioned a service
print()
print("=" * 50)
print("5. BLUEPRINT TOKEN vs KNOWN SERVICE URLS")
print("=" * 50)
service_urls = [
    f"{proj}/agents",
    f"{proj}/agents/{agent_name}",
    f"{proj}/agents/{agent_name}/sessions",
    f"{proj}/agents/{agent_name}/sessions/{session_id}",
    f"{proj}/toolboxes",
    f"{proj}/toolboxes/{agent_name}",
    f"{proj}/openai/v1/models",
    f"https://{acct}.services.ai.azure.com/agents",
    f"https://{acct}.services.ai.azure.com/agents/{agent_name}",
]
for url in service_urls:
    for av in ["2025-05-15-preview", "2025-01-01-preview", "v1"]:
        sep = "&" if "?" in url else "?"
        full = f"{url}{sep}api-version={av}"
        code, hdrs, body = try_url(full, bp_tok)
        if code not in (0, 404, 401):
            print(f"  BP {full[-60:]}: HTTP {code}")
            print(f"    {body[:200]}")
            break
        elif code == 401 and "audience" not in body.lower():
            # 401 but NOT "wrong audience" = the audience IS accepted, just no perms
            print(f"  BP {full[-60:]}: HTTP 401 (audience accepted!)")
            print(f"    {body[:200]}")
            break
    # Also try instance token for comparison on interesting paths
    if "sessions" in url:
        code2, _, body2 = try_url(f"{url}?api-version=2025-05-15-preview", inst_tok)
        if code2 not in (0, 404):
            print(f"  INST {url[-60:]}: HTTP {code2}")
            print(f"    {body2[:200]}")

print()
print("DONE")
