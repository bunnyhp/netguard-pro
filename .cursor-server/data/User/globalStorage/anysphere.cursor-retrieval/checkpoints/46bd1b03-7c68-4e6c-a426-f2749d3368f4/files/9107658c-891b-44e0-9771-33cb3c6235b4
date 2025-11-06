#!/bin/bash

echo "NetGuard Pro - Installing All Missing Services"
echo "=============================================="
echo ""

# Function to install a service
install_service() {
    local service_name=$1
    local description=$2
    
    echo "Installing $description ($service_name)..."
    
    # Copy service file
    if [ -f "/home/jarvis/NetGuard/services/${service_name}.service" ]; then
        sudo cp "/home/jarvis/NetGuard/services/${service_name}.service" "/etc/systemd/system/"
        echo "  ✓ Copied service file"
    else
        echo "  ✗ Service file not found: ${service_name}.service"
        return 1
    fi
    
    # Copy timer file if it exists
    if [ -f "/home/jarvis/NetGuard/services/${service_name}.timer" ]; then
        sudo cp "/home/jarvis/NetGuard/services/${service_name}.timer" "/etc/systemd/system/"
        echo "  ✓ Copied timer file"
    fi
    
    # Enable and start
    sudo systemctl daemon-reload
    sudo systemctl enable "${service_name}.service"
    
    if [ -f "/home/jarvis/NetGuard/services/${service_name}.timer" ]; then
        sudo systemctl enable "${service_name}.timer"
        sudo systemctl start "${service_name}.timer"
        echo "  ✓ Started timer service"
    else
        sudo systemctl start "${service_name}.service"
        echo "  ✓ Started regular service"
    fi
    
    echo ""
}

# Install all missing services
install_service "ai-5min-aggregator" "AI 5-Min Aggregator"
install_service "iot-security-scanner" "IoT Security Scanner"
install_service "device-scorer" "Device Scorer"
install_service "enhanced-alert-system" "Enhanced Alert System"

# Reload systemd daemon
sudo systemctl daemon-reload

echo "Installation completed!"
echo ""
echo "Checking service status:"
echo "========================"

# Check status of all services
services=("ai-5min-aggregator" "iot-security-scanner" "device-scorer" "enhanced-alert-system")

for service in "${services[@]}"; do
    echo -n "Checking $service: "
    
    # Check if it has a timer
    if [ -f "/etc/systemd/system/${service}.timer" ]; then
        if systemctl is-active --quiet "${service}.timer"; then
            echo "RUNNING (timer)"
        else
            echo "STOPPED (timer)"
        fi
    else
        if systemctl is-active --quiet "${service}.service"; then
            echo "RUNNING (service)"
        else
            echo "STOPPED (service)"
        fi
    fi
done

echo ""
echo "Detailed status:"
echo "================"

for service in "${services[@]}"; do
    echo ""
    echo "=== $service ==="
    if [ -f "/etc/systemd/system/${service}.timer" ]; then
        sudo systemctl status "${service}.timer" --no-pager -l
    else
        sudo systemctl status "${service}.service" --no-pager -l
    fi
done

echo ""
echo "All services installed! Check the System Status page in the web interface."
