#!/bin/bash

echo "Restarting Flask to apply IoT page fixes..."

# Stop existing Flask processes
sudo pkill -f "python3.*app.py" 2>/dev/null || true
sleep 2

# Start Flask
cd /home/jarvis/NetGuard/web
nohup python3 app.py > /tmp/flask.log 2>&1 &
sleep 3

echo "Flask restarted. Testing IoT page..."
curl -s -o /dev/null -w "IoT Devices Page: %{http_code}\n" http://localhost:8080/iot-devices
curl -s -o /dev/null -w "Network Traffic API: %{http_code}\n" http://localhost:8080/api/network-traffic-stats

echo "Done! Check http://localhost:8080/iot-devices"
