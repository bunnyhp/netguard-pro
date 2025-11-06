#!/bin/bash

echo "=========================================="
echo "  NetGuard Pro - Install & Start All Services"
echo "=========================================="
echo ""

# List of all collector services
SERVICES=(
    "p0f-collector"
    "tshark-collector"
    "tcpdump-collector"
    "ngrep-collector"
    "httpry-collector"
    "argus-collector"
    "netsniff-collector"
    "iftop-collector"
    "nethogs-collector"
    "suricata-collector"
)

# Install each service
echo "STEP 1: Installing service files..."
echo "----------------------------------------"
for service in "${SERVICES[@]}"; do
    if [ -f "/home/jarvis/NetGuard/services/$service.service" ]; then
        echo "→ Installing $service.service..."
        sudo cp "/home/jarvis/NetGuard/services/$service.service" /etc/systemd/system/
        sudo chmod 644 "/etc/systemd/system/$service.service"
    else
        echo "  ⚠ Warning: $service.service not found"
    fi
done

echo ""
echo "STEP 2: Reloading systemd daemon..."
echo "----------------------------------------"
sudo systemctl daemon-reload
echo "  ✓ Daemon reloaded"

echo ""
echo "STEP 3: Enabling services (auto-start on boot)..."
echo "----------------------------------------"
for service in "${SERVICES[@]}"; do
    if [ -f "/etc/systemd/system/$service.service" ]; then
        echo "→ Enabling $service..."
        sudo systemctl enable $service 2>/dev/null
    fi
done

echo ""
echo "STEP 4: Starting all services..."
echo "----------------------------------------"
for service in "${SERVICES[@]}"; do
    if [ -f "/etc/systemd/system/$service.service" ]; then
        echo "→ Starting $service..."
        sudo systemctl restart $service
        sleep 2
        
        if systemctl is-active --quiet $service; then
            echo "  ✓ $service is RUNNING"
        else
            echo "  ✗ $service FAILED to start"
            echo "  Error details:"
            sudo journalctl -u $service -n 10 --no-pager | tail -5
        fi
    fi
    echo ""
done

echo ""
echo "=========================================="
echo "  Final Status Check"
echo "=========================================="
echo ""

RUNNING=0
STOPPED=0

for service in "${SERVICES[@]}"; do
    if systemctl is-active --quiet $service; then
        echo "✓ $service: RUNNING"
        ((RUNNING++))
    else
        echo "✗ $service: STOPPED"
        ((STOPPED++))
    fi
done

echo ""
echo "----------------------------------------"
echo "Summary: $RUNNING running, $STOPPED stopped"
echo "=========================================="
echo ""

if [ $STOPPED -gt 0 ]; then
    echo "⚠ Some services failed to start."
    echo "Check logs with: sudo journalctl -u <service-name> -n 50"
fi

