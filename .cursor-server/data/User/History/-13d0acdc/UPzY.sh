#!/bin/bash

echo "Starting IoT Security Scanner..."

# Check if systemd service exists
if systemctl list-unit-files | grep -q "^iot-security-scanner.service"; then
    echo "Found systemd service: iot-security-scanner"
    sudo systemctl start iot-security-scanner
    sudo systemctl status iot-security-scanner --no-pager
else
    echo "No systemd service found, starting as script..."
    
    # Kill any existing processes
    pkill -f "iot_security_scanner.py" 2>/dev/null
    
    # Start the script
    cd /home/jarvis/NetGuard/scripts
    nohup python3 iot_security_scanner.py > /tmp/iot_security_scanner.log 2>&1 &
    
    sleep 2
    
    if pgrep -f "iot_security_scanner.py" > /dev/null; then
        echo "✓ IoT Security Scanner started successfully"
        echo "Process ID: $(pgrep -f 'iot_security_scanner.py')"
    else
        echo "✗ Failed to start IoT Security Scanner"
        echo "Check log: /tmp/iot_security_scanner.log"
    fi
fi
