#!/bin/bash

echo "Installing Enhanced IoT Security Scanner..."

# Stop old IoT scanner if running
sudo systemctl stop iot-security-scanner.service 2>/dev/null || true
sudo systemctl disable iot-security-scanner.service 2>/dev/null || true

# Copy new service file
sudo cp /home/jarvis/NetGuard/services/enhanced-iot-security-scanner.service /etc/systemd/system/

# Reload systemd daemon
sudo systemctl daemon-reload

# Enable and start the new service
sudo systemctl enable enhanced-iot-security-scanner.service
sudo systemctl start enhanced-iot-security-scanner.service

echo "Enhanced IoT Security Scanner installed and started."
echo "Checking status:"
sudo systemctl status enhanced-iot-security-scanner.service --no-pager | grep "Active:"

echo ""
echo "Service installed successfully!"
echo "The enhanced IoT scanner will now:"
echo "• Monitor IoT devices for vulnerabilities"
echo "• Track real-time communications"
echo "• Analyze behavioral patterns"
echo "• Generate security scores"
echo "• Create security alerts"
echo "• Track domain communications"
echo ""
echo "Check the IoT devices page for real data!"
