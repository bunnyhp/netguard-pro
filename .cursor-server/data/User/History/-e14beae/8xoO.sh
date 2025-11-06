#!/bin/bash

echo "Fixing IoT Domain Patterns on IoT Security Page..."

echo "1. Checking and populating iot_domain_patterns table..."
python3 /home/jarvis/NetGuard/CHECK_IOT_DOMAIN_PATTERNS.py

echo ""
echo "2. Starting Enhanced IoT Security Scanner..."
sudo systemctl stop enhanced-iot-security-scanner.service 2>/dev/null || true
sudo systemctl start enhanced-iot-security-scanner.service

echo ""
echo "3. Checking Enhanced IoT Security Scanner status..."
sudo systemctl status enhanced-iot-security-scanner.service --no-pager | grep "Active:"

echo ""
echo "4. Restarting Flask to refresh data..."
sudo pkill -f "python3.*app.py" 2>/dev/null || true
sleep 3

cd /home/jarvis/NetGuard/web
nohup python3 app.py > /tmp/flask.log 2>&1 &
sleep 3

echo ""
echo "✅ IoT Domain Patterns fix complete!"
echo "Visit: http://localhost:8080/iot-devices"
echo "The 'Domain Communication Patterns' section should now show data."
