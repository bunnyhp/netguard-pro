#!/bin/bash

echo "NetGuard Pro - Complete Service Management"
echo "=========================================="
echo ""

# Function to check service status
check_service() {
    local service_name=$1
    local script_name=$2
    local display_name=$3
    
    echo -n "Checking $display_name: "
    
    # Check systemd service first
    if systemctl list-unit-files | grep -q "^${service_name}.service"; then
        if systemctl is-active --quiet $service_name; then
            echo "RUNNING (systemd)"
            return 0
        else
            echo "STOPPED (systemd)"
            return 1
        fi
    else
        # Check if script is running
        if pgrep -f "$script_name" > /dev/null; then
            echo "RUNNING (script)"
            return 0
        else
            echo "STOPPED (script)"
            return 1
        fi
    fi
}

# Function to start service
start_service() {
    local service_name=$1
    local script_name=$2
    local display_name=$3
    
    echo "Starting $display_name..."
    
    # Check systemd service first
    if systemctl list-unit-files | grep -q "^${service_name}.service"; then
        sudo systemctl start $service_name
        sleep 2
        if systemctl is-active --quiet $service_name; then
            echo "✓ Started successfully (systemd)"
            return 0
        else
            echo "✗ Failed to start (systemd)"
            return 1
        fi
    else
        # Start as script
        cd /home/jarvis/NetGuard/scripts
        nohup python3 "$script_name" > "/tmp/${script_name}.log" 2>&1 &
        sleep 2
        if pgrep -f "$script_name" > /dev/null; then
            echo "✓ Started successfully (script)"
            return 0
        else
            echo "✗ Failed to start (script)"
            return 1
        fi
    fi
}

# Define all services
declare -A services=(
    ["iot-security-scanner"]="iot_security_scanner.py:IoT Security Scanner"
    ["device-scorer"]="device_scorer.py:Device Scorer"
    ["enhanced-alert-system"]="enhanced_alert_system.py:Enhanced Alert System"
    ["ai-5min-aggregator"]="ai_5min_aggregator.py:AI 5-Min Aggregator"
    ["device-tracker"]="device_tracker.py:Device Tracker"
    ["unified-device-processor"]="unified_device_processor.py:Unified Device Processor"
)

echo "Current Service Status:"
echo "======================"
stopped_services=()

for service in "${!services[@]}"; do
    IFS=':' read -r script display <<< "${services[$service]}"
    if ! check_service "$service" "$script" "$display"; then
        stopped_services+=("$service:$script:$display")
    fi
done

echo ""
if [ ${#stopped_services[@]} -eq 0 ]; then
    echo "✓ All services are running!"
else
    echo "Found ${#stopped_services[@]} stopped services. Starting them now..."
    echo ""
    
    for service_info in "${stopped_services[@]}"; do
        IFS=':' read -r service script display <<< "$service_info"
        start_service "$service" "$script" "$display"
        echo ""
    done
    
    echo "Final Status Check:"
    echo "==================="
    for service in "${!services[@]}"; do
        IFS=':' read -r script display <<< "${services[$service]}"
        check_service "$service" "$script" "$display"
    done
fi

echo ""
echo "Service Management Commands:"
echo "==========================="
echo "Check status: systemctl status <service-name>"
echo "Start service: sudo systemctl start <service-name>"
echo "Stop service: sudo systemctl stop <service-name>"
echo "Restart service: sudo systemctl restart <service-name>"
echo ""
echo "For scripts:"
echo "Check if running: pgrep -f <script-name>"
echo "Stop script: pkill -f <script-name>"
echo ""
echo "Reference file: /home/jarvis/NetGuard/SERVICE_NAMES_REFERENCE.txt"
