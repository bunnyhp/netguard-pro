"""
NetGuard Pro - Configuration Management
Centralized configuration for all paths and settings
"""

import os
from pathlib import Path

# Get project root directory (parent of this file)
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Database configuration
DB_PATH = os.getenv('NETGUARD_DB_PATH', str(PROJECT_ROOT / "network.db"))

# Directory structure
BASE_DIR = PROJECT_ROOT
LOGS_DIR = BASE_DIR / "logs" / "system"
CAPTURES_DIR = BASE_DIR / "captures"
CONFIG_DIR = BASE_DIR / "config"
SCRIPTS_DIR = BASE_DIR / "scripts"
WEB_DIR = BASE_DIR / "web"
SERVICES_DIR = BASE_DIR / "services"

# Ensure directories exist
LOGS_DIR.mkdir(parents=True, exist_ok=True)
CAPTURES_DIR.mkdir(parents=True, exist_ok=True)

# Web configuration
WEB_HOST = os.getenv('NETGUARD_WEB_HOST', '0.0.0.0')
WEB_PORT = int(os.getenv('NETGUARD_WEB_PORT', '8080'))

# Flask secret key (change in production!)
SECRET_KEY = os.getenv('NETGUARD_SECRET_KEY', 'netguard-pro-secure-key-change-in-production')

# Network interfaces (configure for your system)
NETWORK_INTERFACES = {
    'primary': os.getenv('NETGUARD_INTERFACE_PRIMARY', 'eth0'),
    'wifi': os.getenv('NETGUARD_INTERFACE_WIFI', 'wlan0'),
    'usb_wifi': os.getenv('NETGUARD_INTERFACE_USB_WIFI', 'wlan1')
}

# Logging configuration
LOG_FILE = str(LOGS_DIR / "netguard.log")
LOG_LEVEL = os.getenv('NETGUARD_LOG_LEVEL', 'INFO')

