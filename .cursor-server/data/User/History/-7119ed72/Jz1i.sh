#!/bin/bash

echo "Fixing JSON Parsing Issues in AI Aggregator..."

# Stop AI aggregator
sudo systemctl stop ai-5min-aggregator.timer 2>/dev/null
sudo systemctl stop ai-5min-aggregator.service 2>/dev/null

# Copy service files
sudo cp /home/jarvis/NetGuard/services/ai-5min-aggregator.service /etc/systemd/system/
sudo cp /home/jarvis/NetGuard/services/ai-5min-aggregator.timer /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable and start timer
sudo systemctl enable ai-5min-aggregator.timer
sudo systemctl start ai-5min-aggregator.timer

# Restart Flask
sudo pkill -f "python3.*app.py" 2>/dev/null || true
sleep 3

cd /home/jarvis/NetGuard/web
nohup python3 app.py > /tmp/flask.log 2>&1 &
sleep 3

echo "Testing improved JSON parsing..."
python3 /home/jarvis/NetGuard/TEST_AI_AGGREGATOR.py

echo ""
echo "JSON parsing fix complete!"
echo "The AI system now has better error handling for JSON responses."
