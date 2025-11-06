#!/bin/bash

echo "=========================================="
echo "  NetGuard Pro - Collector Diagnostics & Fix"
echo "=========================================="
echo ""

# Ensure log directories exist
echo "→ Creating log directories..."
sudo mkdir -p /home/jarvis/NetGuard/logs/system
sudo mkdir -p /home/jarvis/NetGuard/logs/data
sudo chown -R jarvis:jarvis /home/jarvis/NetGuard/logs
sudo chmod -R 755 /home/jarvis/NetGuard/logs
echo "  ✓ Log directories ready"
echo ""

# Ensure scripts are executable
echo "→ Making collector scripts executable..."
sudo chmod +x /home/jarvis/NetGuard/scripts/*_collector.py
echo "  ✓ Scripts are executable"
echo ""

# Check if required tools are installed
echo "→ Checking required network tools..."
TOOLS=("p0f" "ngrep" "httpry" "netsniff-ng" "nethogs" "argus" "iftop")
MISSING=()

for tool in "${TOOLS[@]}"; do
    if command -v $tool &> /dev/null; then
        echo "  ✓ $tool: installed"
    else
        echo "  ✗ $tool: NOT installed"
        MISSING+=($tool)
    fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
    echo ""
    echo "⚠ Missing tools detected. Installing..."
    sudo apt-get update -qq
    for tool in "${MISSING[@]}"; do
        echo "  → Installing $tool..."
        case $tool in
            "netsniff-ng")
                sudo apt-get install -y netsniff-ng
                ;;
            "argus")
                sudo apt-get install -y argus-client argus-server
                ;;
            *)
                sudo apt-get install -y $tool
                ;;
        esac
    done
fi

echo ""
echo "→ Installing systemd service files..."
sudo cp /home/jarvis/NetGuard/services/*-collector.service /etc/systemd/system/
sudo systemctl daemon-reload
echo "  ✓ Services installed"

echo ""
echo "→ Starting all collector services..."
echo ""

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

for service in "${SERVICES[@]}"; do
    echo "  Starting $service..."
    sudo systemctl enable $service 2>/dev/null
    sudo systemctl restart $service
    sleep 2
    
    if systemctl is-active --quiet $service; then
        echo "    ✓ $service is RUNNING"
    else
        echo "    ✗ $service FAILED"
        echo "    Last 5 log lines:"
        sudo journalctl -u $service -n 5 --no-pager | sed 's/^/      /'
    fi
    echo ""
done

echo "=========================================="
echo "  Collector Status"
echo "=========================================="
echo ""

RUNNING=0
STOPPED=0
TOTAL=${#SERVICES[@]}

for service in "${SERVICES[@]}"; do
    if systemctl is-active --quiet $service; then
        echo "✓ $service"
        ((RUNNING++))
    else
        echo "✗ $service"
        ((STOPPED++))
    fi
done

echo ""
echo "=========================================="
echo "Summary: $RUNNING/$TOTAL services running"
echo "=========================================="
echo ""

# Check if data is being collected
echo "→ Checking database for recent data..."
sleep 5

if sqlite3 /home/jarvis/NetGuard/network.db "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%_2025%' LIMIT 5" | head -5; then
    echo ""
    echo "✓ Data collection is working!"
else
    echo ""
    echo "⚠ No recent data tables found. Collectors may need more time."
fi

echo ""
echo "To view logs: sudo journalctl -u <service-name> -f"
echo "To restart a service: sudo systemctl restart <service-name>"

