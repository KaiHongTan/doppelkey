#!/bin/sh
[ -f /tmp/keeper.pid ] && kill "$(cat /tmp/keeper.pid)" 2>/dev/null
sleep 0.3
node keeper.mjs > /tmp/keeper.out 2>&1 &
echo $! > /tmp/keeper.pid
sleep 0.5
