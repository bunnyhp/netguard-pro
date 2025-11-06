#!/bin/bash

# Ensure capture directory exists
mkdir -p /home/jarvis/NetGuard/captures/p0f
chmod 755 /home/jarvis/NetGuard/captures/p0f

# Kill any existing p0f
sudo pkill -9 p0f
sleep 1

# Start p0f on wlo1 interface
sudo p0f -i wlo1 -o /home/jarvis/NetGuard/captures/p0f/p0f.log -d

# Wait and check
sleep 3
ps aux | grep p0f | grep -v grep

echo "p0f started. Check log: tail -f /home/jarvis/NetGuard/captures/p0f/p0f.log"

