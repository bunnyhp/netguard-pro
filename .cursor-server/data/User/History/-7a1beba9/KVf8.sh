#!/bin/bash

echo "Starting Enhanced Alert System..."

# Check if systemd service exists
if systemctl list-unit-files | grep -q "^enhanced-alert-system.service"; then
    echo "Found systemd service: enhanced-alert-system"
    sudo systemctl start enhanced-alert-system
    sudo systemctl status enhanced-alert-system --no-pager
else
    echo "No systemd service found, starting as script..."
    
    # Kill any existing processes
    pkill -f "enhanced_alert_system.py" 2>/dev/null
    
    # Start the script
    cd /home/jarvis/NetGuard/scripts
    nohup python3 enhanced_alert_system.py > /tmp/enhanced_alert_system.log 2>&1 &
    
    sleep 2
    
    if pgrep -f "enhanced_alert_system.py" > /dev/null; then
        echo "✓ Enhanced Alert System started successfully"
        echo "Process ID: $(pgrep -f 'enhanced_alert_system.py')"
    else
        echo "✗ Failed to start Enhanced Alert System"
        echo "Check log: /tmp/enhanced_alert_system.log"
    fi
fi
