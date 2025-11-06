#!/bin/bash

echo "Fixing AI 5-Minute Aggregator..."

# Check current status
echo "Checking AI aggregator status..."
sudo systemctl status ai-5min-aggregator.timer --no-pager | grep "Active:"
sudo systemctl status ai-5min-aggregator.service --no-pager | grep "Active:"

echo ""
echo "Installing and starting AI aggregator services..."

# Copy service files to systemd
sudo cp /home/jarvis/NetGuard/services/ai-5min-aggregator.service /etc/systemd/system/
sudo cp /home/jarvis/NetGuard/services/ai-5min-aggregator.timer /etc/systemd/system/

# Reload systemd daemon
sudo systemctl daemon-reload

# Enable and start the timer
sudo systemctl enable ai-5min-aggregator.timer
sudo systemctl start ai-5min-aggregator.timer

# Enable and start the service
sudo systemctl enable ai-5min-aggregator.service

echo ""
echo "Checking status after fix..."
sudo systemctl status ai-5min-aggregator.timer --no-pager | grep "Active:"
sudo systemctl status ai-5min-aggregator.service --no-pager | grep "Active:"

echo ""
echo "Checking recent AI analysis data..."
sqlite3 /home/jarvis/NetGuard/network.db "SELECT COUNT(*) as total_analysis FROM ai_analysis;"
sqlite3 /home/jarvis/NetGuard/network.db "SELECT timestamp, threats_detected FROM ai_analysis ORDER BY timestamp DESC LIMIT 3;"

echo ""
echo "AI aggregator fix complete!"
echo "The AI dashboard should now show fresh data as the aggregator runs every 5 minutes."