#!/bin/bash

echo "Cleaning up all p0f processes..."

# Kill ALL p0f processes
sudo pkill -9 p0f
sleep 2

# Kill ALL p0f collector scripts
sudo pkill -9 -f p0f_collector.py
sleep 2

# Verify everything is dead
if pgrep -x p0f > /dev/null; then
    echo "WARNING: p0f still running!"
    ps aux | grep p0f | grep -v grep
else
    echo "✓ All p0f processes killed"
fi

if pgrep -f p0f_collector.py > /dev/null; then
    echo "WARNING: p0f collector still running!"
    ps aux | grep p0f_collector | grep -v grep
else
    echo "✓ All p0f collectors killed"
fi

# Clear old log
sudo rm -f /home/jarvis/NetGuard/captures/p0f/p0f.log
sudo rm -f /home/jarvis/NetGuard/logs/system/p0f_position.txt

echo ""
echo "Starting fresh p0f collector via systemd..."
sudo systemctl restart p0f-collector.service

sleep 5

echo ""
echo "Current status:"
echo "=============================================="
echo "p0f processes:"
ps aux | grep "p0f -i" | grep -v grep

echo ""
echo "p0f collector processes:"
ps aux | grep p0f_collector.py | grep -v grep

echo ""
echo "Systemd service status:"
systemctl is-active p0f-collector.service

echo ""
echo "Log file status:"
ls -lh /home/jarvis/NetGuard/captures/p0f/p0f.log 2>/dev/null || echo "Log file does not exist yet (will be created)"

echo ""
echo "=============================================="
echo "Wait 30 seconds then check:"
echo "sudo tail -f /home/jarvis/NetGuard/captures/p0f/p0f.log"
echo "=============================================="

