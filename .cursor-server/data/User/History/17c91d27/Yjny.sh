#!/bin/bash

echo "Fixing IoT devices page..."

# Kill Flask
sudo pkill -f "python3.*app.py" 2>/dev/null || true
sleep 3

# Force kill if still running
sudo pkill -9 -f "python3.*app.py" 2>/dev/null || true
sleep 2

# Start Flask with simplified IoT route
cd /home/jarvis/NetGuard/web
echo "Starting Flask with simplified IoT devices route..."
nohup python3 app.py > /tmp/flask.log 2>&1 &

sleep 5

# Check if it's running
if pgrep -f "python3.*app.py" > /dev/null; then
    echo "✅ Flask restarted successfully!"
    echo "Testing IoT devices page..."
    
    # Test the page
    sleep 2
    response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/iot-devices)
    
    if [ "$response" = "200" ]; then
        echo "✅ IoT devices page is working! (HTTP 200)"
        echo "Visit: http://localhost:8080/iot-devices"
    else
        echo "❌ IoT devices page still has issues (HTTP $response)"
        echo "Flask logs:"
        tail -10 /tmp/flask.log
    fi
else
    echo "❌ Flask failed to start"
    echo "Flask logs:"
    cat /tmp/flask.log
fi
