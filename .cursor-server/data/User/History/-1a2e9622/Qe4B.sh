#!/bin/bash
echo "Stopping Flask..."
pkill -9 -f "python3.*app.py"
sleep 2

echo "Starting Flask..."
cd /home/jarvis/NetGuard/web
nohup python3 app.py > /tmp/flask.log 2>&1 &
sleep 3

echo "Checking Flask status..."
if pgrep -f "python3.*app.py" > /dev/null; then
    echo "✓ Flask is running"
    echo "✓ Dashboard: http://localhost:8080"
    echo "✓ p0f data: http://localhost:8080/analysis/p0f"
else
    echo "✗ Flask failed to start"
    echo "Check logs: cat /tmp/flask.log"
fi

