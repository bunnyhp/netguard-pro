#!/bin/bash

echo "Installing AI 5-Min Aggregator Service..."
echo "========================================="

# Copy service files to systemd
sudo cp /home/jarvis/NetGuard/services/ai-5min-aggregator.service /etc/systemd/system/
sudo cp /home/jarvis/NetGuard/services/ai-5min-aggregator.timer /etc/systemd/system/

# Reload systemd daemon
sudo systemctl daemon-reload

# Enable and start the timer (not the service directly)
sudo systemctl enable ai-5min-aggregator.timer
sudo systemctl start ai-5min-aggregator.timer

# Enable the service (but don't start it - the timer will start it)
sudo systemctl enable ai-5min-aggregator.service

echo ""
echo "Service installation completed!"
echo ""

# Check status
echo "Checking service status:"
echo "========================"
sudo systemctl status ai-5min-aggregator.service --no-pager
echo ""
echo "Checking timer status:"
echo "======================"
sudo systemctl status ai-5min-aggregator.timer --no-pager
echo ""
echo "List of active timers:"
echo "======================"
sudo systemctl list-timers --no-pager | grep ai

echo ""
echo "Service files installed:"
echo "- /etc/systemd/system/ai-5min-aggregator.service"
echo "- /etc/systemd/system/ai-5min-aggregator.timer"
echo ""
echo "To check if it's working:"
echo "sudo systemctl list-timers | grep ai"
echo "sudo journalctl -u ai-5min-aggregator.service -f"
