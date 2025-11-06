#!/bin/bash

echo "=========================================="
echo "  Starting All NetGuard Services"
echo "=========================================="
echo ""

# List of services to start
SERVICES=(
    "p0f-collector"
    "ngrep-collector"
    "httpry-collector"
    "netsniff-collector"
    "nethogs-collector"
)

# Start each service
for service in "${SERVICES[@]}"; do
    echo "→ Starting $service..."
    
    # Check if service file exists
    if [ -f "/etc/systemd/system/$service.service" ]; then
        sudo systemctl start $service
        sleep 2
        
        if systemctl is-active --quiet $service; then
            echo "  ✓ $service is now RUNNING"
        else
            echo "  ✗ $service failed to start"
            echo "  Checking logs..."
            sudo journalctl -u $service -n 20 --no-pager
        fi
    else
        echo "  ⚠ Service file not found: /etc/systemd/system/$service.service"
    fi
    echo ""
done

echo "=========================================="
echo "  Service Status Summary"
echo "=========================================="
echo ""

systemctl is-active p0f-collector && echo "✓ p0f-collector: RUNNING" || echo "✗ p0f-collector: STOPPED"
systemctl is-active ngrep-collector && echo "✓ ngrep-collector: RUNNING" || echo "✗ ngrep-collector: STOPPED"
systemctl is-active httpry-collector && echo "✓ httpry-collector: RUNNING" || echo "✗ httpry-collector: STOPPED"
systemctl is-active argus-collector && echo "✓ argus-collector: RUNNING" || echo "✗ argus-collector: STOPPED"
systemctl is-active netsniff-collector && echo "✓ netsniff-collector: RUNNING" || echo "✗ netsniff-collector: STOPPED"
systemctl is-active iftop-collector && echo "✓ iftop-collector: RUNNING" || echo "✗ iftop-collector: RUNNING"
systemctl is-active nethogs-collector && echo "✓ nethogs-collector: RUNNING" || echo "✗ nethogs-collector: STOPPED"

echo ""
echo "=========================================="

