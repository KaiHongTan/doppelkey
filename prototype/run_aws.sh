#!/bin/sh
# run_aws.sh <node|python> <shim|control>: run an AWS app, verify its signatures, scan its memory.
# "control" runs WITHOUT the shim and WITH the real secret, to show the scanner does find it.
cd "$(dirname "$0")"
LANG_=$1; MODE=$2; OUT=/tmp/aws.$LANG_.$MODE.json; rm -f $OUT
E="$(cat .env.aws | xargs)"
if [ "$MODE" = control ]; then E="$(echo $E | sed 's#AWS_SECRET_ACCESS_KEY=[^ ]*#AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY#')"; fi
if [ "$LANG_" = node ]; then
  if [ "$MODE" = shim ]; then CMD="node --require ./shim.cjs aws.mjs"; else CMD="node aws.mjs"; fi
else
  if [ "$MODE" = shim ]; then CMD="env PYTHONPATH=./pyshim python3 aws.py"; else CMD="python3 aws.py"; fi
fi
env $E OUT=$OUT $CMD > /tmp/aws.app.out 2>&1 &
APP=$!
for i in $(seq 1 100); do [ -f $OUT ] && break; sleep 0.2; done
sleep 0.5
PID=$(grep READY /tmp/aws.app.out | awk '{print $2}')
[ -z "$PID" ] && { cat /tmp/aws.app.out; kill $APP; exit 1; }
node aws_oracle.mjs $OUT
python3 memscan.py $PID /tmp/aws.needles
kill $APP 2>/dev/null
