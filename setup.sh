#!/bin/bash
# NetGuard Pro - Setup Script
# This script helps set up NetGuard Pro for first-time use

set -e

echo "=========================================="
echo "  NetGuard Pro Setup"
echo "=========================================="
echo ""

# Get project root directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$SCRIPT_DIR"
NETGUARD_DIR="$PROJECT_ROOT/NetGuard"

# Check if we're in the right directory
if [ ! -d "$NETGUARD_DIR" ]; then
    echo "Error: NetGuard directory not found at $NETGUARD_DIR"
    echo "Please run this script from the project root directory"
    exit 1
fi

cd "$NETGUARD_DIR"

echo "Step 1: Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is not installed"
    exit 1
fi
python3 --version
echo "✓ Python found"
echo ""

echo "Step 2: Installing Python dependencies..."
if [ -f "$PROJECT_ROOT/requirements.txt" ]; then
    pip3 install -r "$PROJECT_ROOT/requirements.txt"
else
    echo "Warning: requirements.txt not found, installing basic dependencies..."
    pip3 install Flask requests
fi
echo "✓ Dependencies installed"
echo ""

echo "Step 3: Setting up configuration..."
if [ ! -f "config/ai_config.json" ] && [ -f "config/ai_config.json.template" ]; then
    echo "Creating ai_config.json from template..."
    cp config/ai_config.json.template config/ai_config.json
    echo "⚠ Please edit config/ai_config.json and add your API keys"
fi
echo "✓ Configuration files ready"
echo ""

echo "Step 4: Creating necessary directories..."
mkdir -p logs/system
mkdir -p captures/{tcpdump,suricata,tshark,p0f,argus,ngrep,netsniff,httpry,iftop,nethogs,processed_json}
echo "✓ Directories created"
echo ""

echo "Step 5: Initializing database..."
if [ -f "scripts/init_database.py" ]; then
    python3 scripts/init_database.py
    echo "✓ Database initialized"
else
    echo "⚠ Warning: init_database.py not found"
fi
echo ""

echo "Step 6: Setting script permissions..."
find scripts -name "*.sh" -exec chmod +x {} \;
find scripts -name "*.py" -exec chmod +x {} \;
echo "✓ Permissions set"
echo ""

echo "=========================================="
echo "  Setup Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Configure network interfaces in config.py or set environment variables"
echo "2. Edit config/ai_config.json if you want to use AI features"
echo "3. Copy service files to systemd (if using systemd):"
echo "   sudo cp services/*.service /etc/systemd/system/"
echo "   sudo systemctl daemon-reload"
echo "4. Start services (see README.md for details)"
echo "5. Access the dashboard at http://localhost:8080"
echo ""
echo "For detailed setup instructions, see README.md"
echo ""

