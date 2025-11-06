#!/bin/bash
##############################################################################
# System Readiness Check for Thesis Experiments
# Verifies all components are operational before starting 45-day campaign
##############################################################################

echo "======================================================================="
echo "RASPBERRY PI THESIS PROJECT - SYSTEM READINESS CHECK"
echo "======================================================================="
echo ""

READY=true

# Check 1: Directory Structure
echo "[1/10] Checking directory structure..."
for dir in experiments data/baseline data/iot_profiling data/attack_simulation data/performance figures tables logs; do
    if [ -d "/home/jarvis/thesis/$dir" ]; then
        echo "  ✓ $dir exists"
    else
        echo "  ✗ $dir missing!"
        READY=false
    fi
done
echo ""

# Check 2: Executable Scripts
echo "[2/10] Checking executable scripts..."
for script in experiments/baseline_monitor.sh experiments/iot_profiler.py experiments/attack_simulator.sh experiments/performance_benchmark.py experiments/export_statistics.py experiments/generate_figures.py; do
    if [ -x "/home/jarvis/thesis/$script" ]; then
        echo "  ✓ $script is executable"
    else
        echo "  ✗ $script not executable!"
        READY=false
    fi
done
echo ""

# Check 3: Python Dependencies
echo "[3/10] Checking Python dependencies..."
python3 -c "import sys; sys.exit(0)" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "  ✓ Python 3 installed"
    
    for pkg in psutil matplotlib numpy requests sqlite3; do
        python3 -c "import $pkg" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "  ✓ $pkg available"
        else
            echo "  ✗ $pkg missing! Install with: pip3 install $pkg"
            READY=false
        fi
    done
else
    echo "  ✗ Python 3 not found!"
    READY=false
fi
echo ""

# Check 4: Database Access
echo "[4/10] Checking database access..."
if [ -f "/home/jarvis/NetGuard/network.db" ]; then
    echo "  ✓ Database file exists"
    
    table_count=$(sqlite3 /home/jarvis/NetGuard/network.db "SELECT COUNT(*) FROM sqlite_master WHERE type='table';" 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo "  ✓ Database accessible ($table_count tables)"
    else
        echo "  ✗ Cannot query database!"
        READY=false
    fi
else
    echo "  ✗ Database file not found!"
    READY=false
fi
echo ""

# Check 5: Network Interfaces
echo "[5/10] Checking network interfaces..."
for iface in eno1 wlo1; do
    if ip link show $iface &>/dev/null; then
        echo "  ✓ $iface exists"
    else
        echo "  ⚠ $iface not found (may be optional)"
    fi
done
echo ""

# Check 6: Monitoring Services
echo "[6/10] Checking monitoring services..."
service_count=0
for service in tshark-collector suricata-collector p0f-collector; do
    if systemctl is-active --quiet $service.service; then
        echo "  ✓ $service is active"
        ((service_count++))
    else
        echo "  ⚠ $service is not active"
    fi
done

if [ $service_count -ge 1 ]; then
    echo "  ✓ At least one collector service is running"
else
    echo "  ✗ No collector services running!"
    READY=false
fi
echo ""

# Check 7: Disk Space
echo "[7/10] Checking disk space..."
available_gb=$(df -BG /home/jarvis | awk 'NR==2 {print $4}' | tr -d 'G')
if [ "$available_gb" -gt 50 ]; then
    echo "  ✓ Sufficient disk space (${available_gb}GB available)"
else
    echo "  ⚠ Low disk space (${available_gb}GB available, recommend 50+ GB)"
    if [ "$available_gb" -lt 20 ]; then
        READY=false
    fi
fi
echo ""

# Check 8: Memory
echo "[8/10] Checking system memory..."
total_mem_gb=$(free -g | awk 'NR==2 {print $2}')
if [ "$total_mem_gb" -ge 4 ]; then
    echo "  ✓ Sufficient memory (${total_mem_gb}GB)"
else
    echo "  ⚠ Low memory (${total_mem_gb}GB, recommend 4+ GB)"
fi
echo ""

# Check 9: LaTeX Installation (for paper compilation)
echo "[9/10] Checking LaTeX installation..."
if command -v pdflatex &>/dev/null; then
    echo "  ✓ LaTeX installed (pdflatex found)"
else
    echo "  ⚠ LaTeX not installed (needed for paper compilation)"
    echo "    Install with: sudo apt-get install texlive-full"
fi
echo ""

# Check 10: Paper Files
echo "[10/10] Checking paper files..."
if [ -f "/home/jarvis/thesis/paper.tex" ]; then
    lines=$(wc -l < /home/jarvis/thesis/paper.tex)
    echo "  ✓ paper.tex exists ($lines lines)"
else
    echo "  ✗ paper.tex not found!"
    READY=false
fi

if [ -f "/home/jarvis/thesis/references.bib" ]; then
    citations=$(grep -c "@" /home/jarvis/thesis/references.bib)
    echo "  ✓ references.bib exists ($citations citations)"
else
    echo "  ✗ references.bib not found!"
    READY=false
fi
echo ""

# Final Status
echo "======================================================================="
if [ "$READY" = true ]; then
    echo "✓ SYSTEM IS READY FOR EXPERIMENTAL CAMPAIGN!"
    echo ""
    echo "Next steps:"
    echo "  1. Start baseline monitoring:"
    echo "     cd /home/jarvis/thesis"
    echo "     nohup bash experiments/baseline_monitor.sh > logs/baseline.out 2>&1 &"
    echo ""
    echo "  2. Monitor progress:"
    echo "     tail -f logs/baseline_monitor.log"
    echo ""
    echo "  3. Continue writing paper:"
    echo "     nano paper.tex"
    echo ""
else
    echo "✗ SYSTEM NOT READY - FIX ISSUES ABOVE FIRST"
    echo ""
    echo "Common fixes:"
    echo "  - Install Python packages: pip3 install -r requirements.txt"
    echo "  - Start collector services: sudo systemctl start *-collector.service"
    echo "  - Free up disk space: df -h"
    echo ""
fi
echo "======================================================================="

