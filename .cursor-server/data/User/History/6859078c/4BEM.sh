#!/bin/bash

echo "Restarting Flask with updated system health page..."

# Stop Flask
sudo pkill -f "python3.*app.py" 2>/dev/null || true
sleep 3

# Start Flask
cd /home/jarvis/NetGuard/web
nohup python3 app.py > /tmp/flask.log 2>&1 &

sleep 3

if pgrep -f "python3.*app.py" > /dev/null; then
    echo "✅ Flask restarted successfully!"
    echo "System health page now includes:"
    echo "  • ai-5min-aggregator.timer"
    echo "  • ai-5min-aggregator.service"
    echo "  • device-scorer.timer"
    echo "  • device-scorer.service"
    echo "  • enhanced-iot-security-scanner"
    echo "  • All other missing services"
    echo ""
    echo "Visit: http://localhost:8080/system-status"
else
    echo "❌ Flask failed to start"
    cat /tmp/flask.log
fi
