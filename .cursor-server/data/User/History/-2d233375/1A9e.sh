#!/bin/bash

echo "NetGuard Pro - Service Repair Script"
echo "===================================="
echo ""

# Function to check and fix a service
fix_service() {
    local service_name=$1
    local script_name=$2
    local description=$3
    
    echo "Checking: $description ($service_name)"
    
    # Check if it's a systemd service
    if systemctl list-unit-files | grep -q "^${service_name}.service"; then
        echo "  Found systemd service: $service_name"
        
        # Check status
        if systemctl is-active --quiet $service_name; then
            echo "  ✓ Service is already running"
        else
            echo "  → Starting systemd service..."
            sudo systemctl start $service_name
            sleep 2
            
            if systemctl is-active --quiet $service_name; then
                echo "  ✓ Service started successfully"
            else
                echo "  ✗ Failed to start service"
                systemctl status $service_name --no-pager -l
            fi
        fi
    else
        echo "  No systemd service found, checking for script..."
        
        # Check if script is running
        if pgrep -f "$script_name" > /dev/null; then
            echo "  ✓ Script is already running"
        else
            echo "  → Starting script..."
            
            # Check if script file exists
            if [ -f "/home/jarvis/NetGuard/scripts/$script_name" ]; then
                cd /home/jarvis/NetGuard/scripts
                nohup python3 "$script_name" > /dev/null 2>&1 &
                sleep 2
                
                if pgrep -f "$script_name" > /dev/null; then
                    echo "  ✓ Script started successfully"
                else
                    echo "  ✗ Failed to start script"
                fi
            else
                echo "  ✗ Script file not found: $script_name"
            fi
        fi
    fi
    echo ""
}

# Fix all the services
echo "Fixing IoT Security Scanner..."
fix_service "iot-security-scanner" "iot_security_scanner.py" "IoT Security Scanner"

echo "Fixing Device Scorer..."
fix_service "device-scorer" "device_scorer.py" "Device Scorer"

echo "Fixing Enhanced Alert System..."
fix_service "enhanced-alert-system" "enhanced_alert_system.py" "Enhanced Alert System"

echo "Checking other important services..."

# Check AI aggregator
fix_service "ai-5min-aggregator" "ai_5min_aggregator.py" "AI 5-Min Aggregator"

# Check device tracker
fix_service "device-tracker" "device_tracker.py" "Device Tracker"

# Check unified device processor
fix_service "unified-device-processor" "unified_device_processor.py" "Unified Device Processor"

echo "Service repair completed!"
echo ""
echo "Final status check:"
echo "==================="

# Show final status
services=(
    "iot-security-scanner:iot_security_scanner.py"
    "device-scorer:device_scorer.py"
    "enhanced-alert-system:enhanced_alert_system.py"
    "ai-5min-aggregator:ai_5min_aggregator.py"
    "device-tracker:device_tracker.py"
    "unified-device-processor:unified_device_processor.py"
)

for service_info in "${services[@]}"; do
    service_name=$(echo $service_info | cut -d: -f1)
    script_name=$(echo $service_info | cut -d: -f2)
    
    if systemctl list-unit-files | grep -q "^${service_name}.service"; then
        if systemctl is-active --quiet $service_name; then
            echo "✓ $service_name (systemd service) - RUNNING"
        else
            echo "✗ $service_name (systemd service) - STOPPED"
        fi
    else
        if pgrep -f "$script_name" > /dev/null; then
            echo "✓ $service_name (script) - RUNNING"
        else
            echo "✗ $service_name (script) - STOPPED"
        fi
    fi
done

echo ""
echo "Use the SERVICE_NAMES_REFERENCE.txt file for command reference."
