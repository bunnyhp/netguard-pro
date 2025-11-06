#!/bin/bash

echo "NetGuard Pro - Starting All Stopped Services"
echo "============================================"
echo ""

# Function to start a service
start_service() {
    local service_name=$1
    local script_name=$2
    local display_name=$3
    
    echo "Starting $display_name..."
    
    # First, install the service if it doesn't exist
    if [ ! -f "/etc/systemd/system/${service_name}.service" ]; then
        echo "  Installing service file..."
        if [ -f "/home/jarvis/NetGuard/services/${service_name}.service" ]; then
            sudo cp "/home/jarvis/NetGuard/services/${service_name}.service" "/etc/systemd/system/"
            sudo cp "/home/jarvis/NetGuard/services/${service_name}.timer" "/etc/systemd/system/" 2>/dev/null
            sudo systemctl daemon-reload
            echo "  ✓ Service installed"
        else
            echo "  ✗ Service file not found, starting as script..."
            cd /home/jarvis/NetGuard/scripts
            nohup python3 "$script_name" > "/tmp/${script_name}.log" 2>&1 &
            sleep 2
            if pgrep -f "$script_name" > /dev/null; then
                echo "  ✓ Script started"
            else
                echo "  ✗ Script failed to start"
            fi
            return
        fi
    fi
    
    # Enable and start the service
    sudo systemctl enable "${service_name}.service"
    
    # Check if it has a timer
    if [ -f "/etc/systemd/system/${service_name}.timer" ]; then
        sudo systemctl enable "${service_name}.timer"
        sudo systemctl start "${service_name}.timer"
        echo "  ✓ Timer started"
    else
        sudo systemctl start "${service_name}.service"
        echo "  ✓ Service started"
    fi
    
    sleep 2
    
    # Check if it's running
    if [ -f "/etc/systemd/system/${service_name}.timer" ]; then
        if systemctl is-active --quiet "${service_name}.timer"; then
            echo "  ✓ $display_name is now RUNNING (timer)"
        else
            echo "  ✗ $display_name failed to start (timer)"
        fi
    else
        if systemctl is-active --quiet "${service_name}.service"; then
            echo "  ✓ $display_name is now RUNNING (service)"
        else
            echo "  ✗ $display_name failed to start (service)"
        fi
    fi
    
    echo ""
}

# Start all the stopped services
start_service "ai-5min-aggregator" "ai_5min_aggregator.py" "AI 5-Min Aggregator"
start_service "iot-security-scanner" "iot_security_scanner.py" "IoT Security Scanner"
start_service "device-scorer" "device_scorer.py" "Device Scorer"
start_service "enhanced-alert-system" "enhanced_alert_system.py" "Enhanced Alert System"

echo "Starting process completed!"
echo ""
echo "Final Status Check:"
echo "==================="

# Quick status check
services=("ai-5min-aggregator" "iot-security-scanner" "device-scorer" "enhanced-alert-system")
scripts=("ai_5min_aggregator.py" "iot_security_scanner.py" "device_scorer.py" "enhanced_alert_system.py")

for i in "${!services[@]}"; do
    service="${services[$i]}"
    script="${scripts[$i]}"
    
    echo -n "$service: "
    
    # Check systemd first
    if [ -f "/etc/systemd/system/${service}.timer" ]; then
        if systemctl is-active --quiet "${service}.timer"; then
            echo "RUNNING (timer)"
        else
            echo "STOPPED (timer)"
        fi
    elif [ -f "/etc/systemd/system/${service}.service" ]; then
        if systemctl is-active --quiet "${service}.service"; then
            echo "RUNNING (service)"
        else
            echo "STOPPED (service)"
        fi
    else
        # Check script
        if pgrep -f "$script" > /dev/null; then
            echo "RUNNING (script)"
        else
            echo "STOPPED (script)"
        fi
    fi
done

echo ""
echo "Check the System Status page in the web interface to see updated status!"
