#!/bin/bash

echo "NetGuard Pro - Service Status Checker"
echo "====================================="
echo ""

# Function to check service status
check_service() {
    local service_name=$1
    local script_name=$2
    local display_name=$3
    
    echo "=== $display_name ==="
    echo "Service: $service_name"
    echo "Script: $script_name"
    
    # Check systemd service
    if [ -f "/etc/systemd/system/${service_name}.service" ]; then
        echo "✓ Service file exists"
        if systemctl is-active --quiet "${service_name}.service"; then
            echo "✓ Service is ACTIVE"
        else
            echo "✗ Service is INACTIVE"
        fi
    else
        echo "✗ Service file NOT FOUND"
    fi
    
    # Check timer if exists
    if [ -f "/etc/systemd/system/${service_name}.timer" ]; then
        echo "✓ Timer file exists"
        if systemctl is-active --quiet "${service_name}.timer"; then
            echo "✓ Timer is ACTIVE"
        else
            echo "✗ Timer is INACTIVE"
        fi
    fi
    
    # Check if script is running
    if pgrep -f "$script_name" > /dev/null; then
        echo "✓ Script is RUNNING (PID: $(pgrep -f "$script_name"))"
    else
        echo "✗ Script is NOT RUNNING"
    fi
    
    echo ""
}

# Check all services
check_service "ai-5min-aggregator" "ai_5min_aggregator.py" "AI 5-Min Aggregator"
check_service "iot-security-scanner" "iot_security_scanner.py" "IoT Security Scanner"
check_service "device-scorer" "device_scorer.py" "Device Scorer"
check_service "enhanced-alert-system" "enhanced_alert_system.py" "Enhanced Alert System"

echo "Systemd Services Summary:"
echo "========================="
systemctl list-units --type=service | grep -E "(ai|iot|device|enhanced)" || echo "No matching services found"

echo ""
echo "Active Timers:"
echo "=============="
systemctl list-timers --no-pager | grep -E "(ai|device)" || echo "No matching timers found"

echo ""
echo "Running Scripts:"
echo "================"
pgrep -f "ai_5min_aggregator.py" && echo "AI Aggregator: $(pgrep -f 'ai_5min_aggregator.py')" || echo "AI Aggregator: NOT RUNNING"
pgrep -f "iot_security_scanner.py" && echo "IoT Scanner: $(pgrep -f 'iot_security_scanner.py')" || echo "IoT Scanner: NOT RUNNING"
pgrep -f "device_scorer.py" && echo "Device Scorer: $(pgrep -f 'device_scorer.py')" || echo "Device Scorer: NOT RUNNING"
pgrep -f "enhanced_alert_system.py" && echo "Alert System: $(pgrep -f 'enhanced_alert_system.py')" || echo "Alert System: NOT RUNNING"
