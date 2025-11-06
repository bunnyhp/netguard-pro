#!/bin/bash

echo "=========================================="
echo "P0F FINAL FIX"
echo "=========================================="

# 1. Stop everything
echo "[1/7] Stopping all p0f processes and collectors..."
sudo pkill -9 p0f
sudo pkill -9 -f p0f_collector.py
sleep 2

# 2. Delete old tracking files
echo "[2/7] Deleting position tracking file..."
sudo rm -f /home/jarvis/NetGuard/logs/system/p0f_position.txt

# 3. Delete old log
echo "[3/7] Deleting old p0f log..."
sudo rm -f /home/jarvis/NetGuard/captures/p0f/p0f.log

# 4. Verify interface configuration
echo "[4/7] Checking p0f_collector.py interface..."
grep "INTERFACE" /home/jarvis/NetGuard/scripts/p0f_collector.py | head -1

# 5. Start fresh via systemd
echo "[5/7] Starting p0f collector service..."
sudo systemctl restart p0f-collector.service
sleep 5

# 6. Check status
echo "[6/7] Checking status..."
echo ""
echo "p0f tool processes:"
ps aux | grep "p0f -i" | grep -v grep | head -2

echo ""
echo "p0f collector processes:"
ps aux | grep p0f_collector.py | grep -v grep | head -2

echo ""
echo "Systemd service:"
systemctl is-active p0f-collector.service

# 7. Wait and check log
echo ""
echo "[7/7] Waiting 10 seconds for data collection..."
sleep 10

if [ -f "/home/jarvis/NetGuard/captures/p0f/p0f.log" ]; then
    size=$(stat -f%z "/home/jarvis/NetGuard/captures/p0f/p0f.log" 2>/dev/null || stat -c%s "/home/jarvis/NetGuard/captures/p0f/p0f.log")
    echo "p0f log file size: $size bytes"
    if [ $size -gt 0 ]; then
        echo "✓ p0f IS CAPTURING DATA"
        echo ""
        echo "Latest collector log (last 5 lines):"
        sudo tail -5 /home/jarvis/NetGuard/logs/system/p0f-service-error.log
    else
        echo "✗ p0f log is empty (no traffic yet)"
    fi
else
    echo "✗ p0f log file not created"
fi

echo ""
echo "=========================================="
echo "DONE - Check database in 5 minutes:"
echo "python3 /home/jarvis/NetGuard/check_p0f_database.py"
echo "=========================================="

