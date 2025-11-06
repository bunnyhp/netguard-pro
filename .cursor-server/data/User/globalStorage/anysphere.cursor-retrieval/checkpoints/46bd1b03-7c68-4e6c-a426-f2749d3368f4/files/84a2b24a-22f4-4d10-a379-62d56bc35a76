#!/bin/bash

echo "Fixing AI 5-Min Aggregator Service"
echo "=================================="
echo ""

# Install the service files
echo "1. Installing service files..."
sudo cp /home/jarvis/NetGuard/services/ai-5min-aggregator.service /etc/systemd/system/
sudo cp /home/jarvis/NetGuard/services/ai-5min-aggregator.timer /etc/systemd/system/

# Reload systemd
echo "2. Reloading systemd daemon..."
sudo systemctl daemon-reload

# Enable and start
echo "3. Enabling and starting timer..."
sudo systemctl enable ai-5min-aggregator.timer
sudo systemctl start ai-5min-aggregator.timer

echo ""
echo "4. Checking status..."
echo "===================="

echo "Timer status:"
sudo systemctl status ai-5min-aggregator.timer --no-pager
echo ""

echo "Service status:"
sudo systemctl status ai-5min-aggregator.service --no-pager
echo ""

echo "Active timers:"
sudo systemctl list-timers --no-pager | grep ai
echo ""

echo "If you see the timer running, the AI aggregator is working!"
echo ""
echo "To monitor it:"
echo "sudo journalctl -u ai-5min-aggregator.service -f"
