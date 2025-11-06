#!/bin/bash

echo "Restarting Flask with IoT devices page fixes..."

# Stop any existing Flask processes
sudo pkill -f "python3.*app.py" 2>/dev/null || true
sleep 2

# Check if Flask is stopped
if pgrep -f "python3.*app.py" > /dev/null; then
    echo "Force killing Flask processes..."
    sudo pkill -9 -f "python3.*app.py" 2>/dev/null || true
    sleep 2
fi

# Start Flask fresh
cd /home/jarvis/NetGuard/web
echo "Starting Flask with updated IoT devices route..."
nohup python3 app.py > /tmp/flask.log 2>&1 &

sleep 3

# Check if Flask started successfully
if pgrep -f "python3.*app.py" > /dev/null; then
    echo "✅ Flask restarted successfully!"
    echo "Flask PID: $(pgrep -f 'python3.*app.py')"
    echo ""
    echo "Checking Flask logs for any errors..."
    tail -10 /tmp/flask.log
    echo ""
    echo "IoT devices page should now work properly!"
    echo "Visit: http://localhost:8080/iot-devices"
else
    echo "❌ Flask failed to start. Checking logs..."
    cat /tmp/flask.log
fi
