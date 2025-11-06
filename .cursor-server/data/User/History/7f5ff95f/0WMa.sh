#!/bin/bash

# Stop any existing p0f processes
pkill -9 -f p0f_collector.py
pkill -9 p0f
sleep 2

# Start p0f collector
cd /home/jarvis/NetGuard/scripts
nohup python3 p0f_collector.py > /tmp/p0f_collector.log 2>&1 &

echo "p0f collector restarted on wlo1 interface"
echo "Check logs: tail -f /tmp/p0f_collector.log"

