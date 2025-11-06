#!/bin/bash

echo "Starting Device Scorer..."

# Check if systemd service exists
if systemctl list-unit-files | grep -q "^device-scorer.service"; then
    echo "Found systemd service: device-scorer"
    sudo systemctl start device-scorer
    sudo systemctl status device-scorer --no-pager
else
    echo "No systemd service found, starting as script..."
    
    # Kill any existing processes
    pkill -f "device_scorer.py" 2>/dev/null
    
    # Start the script
    cd /home/jarvis/NetGuard/scripts
    nohup python3 device_scorer.py > /tmp/device_scorer.log 2>&1 &
    
    sleep 2
    
    if pgrep -f "device_scorer.py" > /dev/null; then
        echo "✓ Device Scorer started successfully"
        echo "Process ID: $(pgrep -f 'device_scorer.py')"
    else
        echo "✗ Failed to start Device Scorer"
        echo "Check log: /tmp/device_scorer.log"
    fi
fi
