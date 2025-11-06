#!/bin/bash

echo "Installing all missing NetGuard services..."

SERVICE_DIR="/home/jarvis/NetGuard/services"
SYSTEMD_DIR="/etc/systemd/system"

# List of all services to install
ALL_SERVICES=(
    "ai-5min-aggregator.service"
    "ai-5min-aggregator.timer"
    "device-scorer.service"
    "device-scorer.timer"
    "enhanced-alert-system.service"
    "enhanced-iot-security-scanner.service"
    "device-tracker.service"
    "unified-device-processor.service"
    "analysis-tools-collector.service"
    "json-sqlite-converter.service"
    "netguard-flask.service"
    "netguard-monitor.service"
    "network-capture.service"
    "network-dashboard.service"
    "pcap-json-converter.service"
    "flask-dashboard.service"
)

echo "Copying service files to systemd directory..."

for service_file in "${ALL_SERVICES[@]}"; do
    if [ -f "$SERVICE_DIR/$service_file" ]; then
        echo "  Installing $service_file..."
        sudo cp "$SERVICE_DIR/$service_file" "$SYSTEMD_DIR/"
    else
        echo "  Warning: $service_file not found in $SERVICE_DIR"
    fi
done

echo ""
echo "Reloading systemd daemon..."
sudo systemctl daemon-reload

echo ""
echo "Enabling and starting services..."

# Enable all services
for service_file in "${ALL_SERVICES[@]}"; do
    service_name=$(basename "$service_file")
    if [ -f "$SYSTEMD_DIR/$service_name" ]; then
        echo "  Enabling $service_name..."
        sudo systemctl enable "$service_name" 2>/dev/null || true
    fi
done

# Start key services
KEY_SERVICES=(
    "ai-5min-aggregator.timer"
    "device-scorer.timer"
    "enhanced-alert-system.service"
    "enhanced-iot-security-scanner.service"
    "device-tracker.service"
    "unified-device-processor.service"
)

for service in "${KEY_SERVICES[@]}"; do
    if [ -f "$SYSTEMD_DIR/$service" ]; then
        echo "  Starting $service..."
        sudo systemctl start "$service" 2>/dev/null || true
    fi
done

echo ""
echo "Final status check for key services:"
for service in "${KEY_SERVICES[@]}"; do
    echo -n "  $service: "
    sudo systemctl is-active "$service" 2>/dev/null && echo "RUNNING" || echo "STOPPED"
done

echo ""
echo "All services installation complete!"
echo "Check the system health page to see all services and their status."