#!/bin/bash
#
# NetGuard Pro - Network Interface Optimization Script
# Optimizes network interfaces for accurate packet capture
#

echo "======================================================================"
echo "NetGuard Pro - Network Interface Optimization"
echo "======================================================================"
echo ""

# Network interfaces
INTERFACES=("eno1" "wlo1" "wlx1cbfce6265ad")

echo "Optimizing network interfaces for packet capture..."
echo ""

# Disable offloading features for accurate capture
echo "[1/3] Disabling hardware offloading..."
for iface in "${INTERFACES[@]}"; do
    if ip link show "$iface" &> /dev/null; then
        echo "  • $iface: Disabling GRO, LRO, TSO, GSO..."
        sudo ethtool -K "$iface" gro off lro off tso off gso off 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "    ✓ Offloading disabled"
        else
            echo "    ⚠ Some features may not be supported on this interface"
        fi
    else
        echo "  • $iface: Interface not found (skipping)"
    fi
done
echo ""

# Increase ring buffers for better packet capture
echo "[2/3] Increasing ring buffers..."
for iface in "${INTERFACES[@]}"; do
    if ip link show "$iface" &> /dev/null; then
        echo "  • $iface: Setting RX/TX ring buffers to 4096..."
        sudo ethtool -G "$iface" rx 4096 tx 4096 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "    ✓ Ring buffers increased"
        else
            echo "    ⚠ Ring buffer adjustment not supported on this interface"
        fi
    fi
done
echo ""

# Set CPU governor to performance mode
echo "[3/3] Setting CPU governor to performance mode..."
if [ -d "/sys/devices/system/cpu/cpu0/cpufreq" ]; then
    for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        echo performance | sudo tee "$cpu" > /dev/null 2>&1
    done
    echo "  ✓ CPU governor set to performance"
else
    echo "  ⚠ CPU frequency scaling not available"
fi
echo ""

# Increase network buffer sizes (sysctl)
echo "Optimizing kernel network parameters..."
sudo sysctl -w net.core.rmem_max=134217728 > /dev/null 2>&1
sudo sysctl -w net.core.rmem_default=134217728 > /dev/null 2>&1
sudo sysctl -w net.core.wmem_max=134217728 > /dev/null 2>&1
sudo sysctl -w net.core.netdev_max_backlog=5000 > /dev/null 2>&1
echo "  ✓ Network buffers optimized"
echo ""

# Display current settings
echo "======================================================================"
echo "Current Interface Settings:"
echo "======================================================================"
for iface in "${INTERFACES[@]}"; do
    if ip link show "$iface" &> /dev/null; then
        echo ""
        echo "Interface: $iface"
        echo "  Status: $(ip link show $iface | grep -o 'state [A-Z]*' | awk '{print $2}')"
        echo "  IP: $(ip addr show $iface | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)"
        
        # Check offloading status
        gro_status=$(sudo ethtool -k "$iface" 2>/dev/null | grep "generic-receive-offload" | awk '{print $2}')
        echo "  GRO: ${gro_status:-unknown}"
    fi
done
echo ""

echo "======================================================================"
echo "Optimization Complete!"
echo "======================================================================"
echo ""
echo "Note: These settings are temporary and will reset on reboot."
echo "To make them permanent, add this script to crontab:"
echo "  sudo crontab -e"
echo "  @reboot /home/jarvis/NetGuard/scripts/optimize_interfaces.sh"
echo ""

