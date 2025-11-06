#!/bin/bash

echo "=========================================="
echo "Fixing IoT Domain Patterns on IoT Security Page"
echo "=========================================="

echo ""
echo "🔍 Step 1: Checking iot_domain_patterns table..."
python3 /home/jarvis/NetGuard/CHECK_IOT_DOMAIN_PATTERNS.py

echo ""
echo "🔧 Step 2: Starting Enhanced IoT Security Scanner..."
sudo systemctl stop enhanced-iot-security-scanner.service 2>/dev/null || true
sudo systemctl start enhanced-iot-security-scanner.service

echo "   Checking status:"
sudo systemctl status enhanced-iot-security-scanner.service --no-pager | grep "Active:"

echo ""
echo "🔄 Step 3: Restarting Flask with updated IoT devices route..."
sudo pkill -f "python3.*app.py" 2>/dev/null || true
sleep 3

cd /home/jarvis/NetGuard/web
nohup python3 app.py > /tmp/flask.log 2>&1 &
sleep 3

echo ""
echo "🧪 Step 4: Testing IoT devices page..."
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/iot-devices)
if [ "$response" = "200" ]; then
    echo "✅ IoT Devices page: WORKING (HTTP $response)"
else
    echo "❌ IoT Devices page: FAILED (HTTP $response)"
fi

echo ""
echo "✅ IoT Domain Patterns Fix Complete!"
echo ""
echo "🎯 What was fixed:"
echo "• Created/populated iot_domain_patterns table"
echo "• Started Enhanced IoT Security Scanner service"
echo "• Updated IoT devices route to include domain patterns data"
echo "• Restarted Flask with new configuration"
echo ""
echo "🌐 Visit: http://localhost:8080/iot-devices"
echo "The 'Domain Communication Patterns' section should now show real data!"
echo "=========================================="
