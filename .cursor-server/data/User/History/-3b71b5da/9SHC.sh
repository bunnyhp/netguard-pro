#!/bin/bash
echo "Checking if p0f tool is running..."
ps aux | grep "p0f -i" | grep -v grep
if [ $? -eq 0 ]; then
    echo "✓ p0f tool is RUNNING"
else
    echo "✗ p0f tool is NOT running"
    echo ""
    echo "Starting p0f tool on wlo1..."
    sudo p0f -i wlo1 -o /home/jarvis/NetGuard/captures/p0f/p0f.log -d -u root &
    sleep 2
    ps aux | grep "p0f -i" | grep -v grep
    if [ $? -eq 0 ]; then
        echo "✓ p0f tool started successfully"
    else
        echo "✗ Failed to start p0f"
    fi
fi

