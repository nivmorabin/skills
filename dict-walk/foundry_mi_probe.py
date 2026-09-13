#!/usr/bin/env python3
"""Probe which managed identities the MSI endpoint will mint tokens for.

Tests: no client_id, instance MI, blueprint MI, default MI.
For each, decodes the JWT and shows appid/oid/roles/xms_mirid.
"""
import json, base64, os, urllib.request, sys

ep = os.environ["IDENTITY_ENDPOINT"]
hdr = os.environ["IDENTITY_HEADER"]
instance_id = os.environ.get("FOUNDRY_AGENT_INSTANCE_CLIENT_ID", "")
blueprint_id = os.environ.get("FOUNDRY_AGENT_BLUEPRINT_CLIENT_ID", "")
default_id = os.environ.get("FOUNDRY_AGENT_DEFAULT_INSTANCE_CLIENT_ID", "")

print(f"instance MI:  {instance_id}")
print(f"blueprint MI: {blueprint_id}")
print(f"default MI:   {default_id}")
print()

resource = "https://management.azure.com/"
pad = lambda s: s + "=" * (-len(s) % 4)

for label, cid in [
    ("NO client_id", ""),
    ("instance", instance_id),
    ("blueprint", blueprint_id),
    ("default", default_id),
]:
    url = f"{ep}?api-version=2019-08-01&resource={resource}"
    if cid:
        url += f"&client_id={cid}"
    req = urllib.request.Request(url, headers={"X-IDENTITY-HEADER": hdr})
    try:
        with urllib.request.urlopen(req) as r:
            tok = json.load(r)["access_token"]
            claims = json.loads(base64.urlsafe_b64decode(pad(tok.split(".")[1])))
            print(f"{label} (client_id={cid or 'omitted'}):")
            print(f"  appid = {claims.get('appid')}")
            print(f"  oid   = {claims.get('oid')}")
            print(f"  sub   = {claims.get('sub')}")
            print(f"  mirid = {claims.get('xms_mirid', 'n/a')}")
            print(f"  roles = {claims.get('roles', [])}")
            print(f"  scp   = {claims.get('scp', '')}")
            # Check if this identity is different from the instance MI
            if claims.get("appid") != instance_id:
                print(f"  *** DIFFERENT IDENTITY from instance MI! ***")
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:200]
        print(f"{label} (client_id={cid or 'omitted'}): HTTP {e.code}")
        print(f"  {body}")
    except Exception as e:
        print(f"{label} (client_id={cid or 'omitted'}): FAILED - {e}")
    print()

# Also try some made-up client_ids to see if the endpoint validates
print("=== Validation check: bogus client_id ===")
for bogus in ["00000000-0000-0000-0000-000000000000", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"]:
    url = f"{ep}?api-version=2019-08-01&resource={resource}&client_id={bogus}"
    req = urllib.request.Request(url, headers={"X-IDENTITY-HEADER": hdr})
    try:
        with urllib.request.urlopen(req) as r:
            print(f"  {bogus}: SUCCESS (!!)")
    except urllib.error.HTTPError as e:
        print(f"  {bogus}: HTTP {e.code} - {e.read().decode()[:100]}")
    except Exception as e:
        print(f"  {bogus}: {e}")

print("\nDONE")
