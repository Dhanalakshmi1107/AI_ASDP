#!/bin/bash
PROJ="/mnt/d/Download Manager/AIASDP/AIASDP"
export PYTHONPATH="$PROJ/venv/lib/python3.13/site-packages"
cd "$PROJ"
nohup python3 -u main.py > /tmp/backend.log 2>&1 &
BGPID=$!
echo "PID: $BGPID"
sleep 15
if kill -0 $BGPID 2>/dev/null; then
    echo "Backend is running"
else
    echo "Backend FAILED to start"
fi
tail -30 /tmp/backend.log
