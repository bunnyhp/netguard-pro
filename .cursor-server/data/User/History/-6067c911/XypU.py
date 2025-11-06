#!/usr/bin/env python3
"""
NetGuard Pro - Device Tracker
Centralized device registry with MAC address tracking, vendor lookup, and device categorization
"""

import os
import sys
import json
import sqlite3
import logging
import subprocess
import re
import socket
from datetime import datetime
from collections import defaultdict

# Configuration
DB_PATH = "/home/jarvis/NetGuard/network.db"
DEVICE_DB_PATH = "/home/jarvis/NetGuard/config/known_devices.json"
MAC_OUI_DB = "/home/jarvis/NetGuard/config/mac_oui.json"
LOG_FILE = "/home/jarvis/NetGuard/logs/system/device-tracker.log"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

class DeviceTracker:
    def __init__(self):
        self.devices = {}
        self.mac_oui_db = self.load_mac_oui_database()
        self.load_known_devices()
        self.init_device_table()
    
    def init_device_table(self):
        """Initialize device tracking table in database"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac_address TEXT UNIQUE,
                    ip_address TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    device_type TEXT,
                    device_category TEXT,
                    first_seen DATETIME,
                    last_seen DATETIME,
                    is_trusted INTEGER DEFAULT 0,
                    notes TEXT,
                    open_ports TEXT,
                    security_score INTEGER DEFAULT 50,
                    total_packets INTEGER DEFAULT 0,
                    total_bytes INTEGER DEFAULT 0
                )
            """)
            
            # Create index for faster lookups
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_mac ON devices(mac_address)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip ON devices(ip_address)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_last_seen ON devices(last_seen)")
            
            conn.commit()
            conn.close()
            logging.info("✓ Device tracking table initialized")
        except Exception as e:
            logging.error(f"Error initializing device table: {e}")
    
    def load_mac_oui_database(self):
        """Load MAC OUI (vendor) database"""
        # Create basic OUI database if doesn't exist
        if not os.path.exists(MAC_OUI_DB):
            # Common vendors for quick identification
            basic_oui = {
                "00:50:56": "VMware",
                "00:0C:29": "VMware",
                "08:00:27": "VirtualBox",
                "52:54:00": "QEMU/KVM",
                "B8:27:EB": "Raspberry Pi Foundation",
                "DC:A6:32": "Raspberry Pi Foundation",
                "E4:5F:01": "Raspberry Pi Foundation",
                "00:1B:44": "Cisco",
                "00:1D:7E": "Cisco",
                "F4:F2:6D": "Google",
                "3C:5A:B4": "Google",
                "A4:77:33": "Google",
                "18:B4:30": "Nest Labs",
                "64:16:66": "Nest Labs",
                "AC:63:BE": "Amazon",
                "FC:65:DE": "Amazon Echo",
                "A4:77:58": "Google Home",
                "F0:EF:86": "Google Home Mini",
                "B4:F0:AB": "Apple",
                "00:17:F2": "Apple",
                "00:1C:B3": "Apple",
                "00:50:F2": "Microsoft",
                "00:15:5D": "Microsoft",
                "30:AE:A4": "Xiaomi",
                "34:CE:00": "Xiaomi",
                "28:6C:07": "TP-Link",
                "50:C7:BF": "TP-Link",
                "00:24:D4": "D-Link",
                "C0:25:E9": "D-Link",
                "00:1F:3F": "Belkin",
                "00:11:50": "Belkin",
                "00:03:7F": "Netgear",
                "E0:46:9A": "Netgear",
                "00:18:F8": "Samsung",
                "34:23:87": "Samsung",
                "00:1A:11": "LG Electronics",
                "A0:B3:CC": "LG Electronics",
                "00:09:18": "Sony",
                "84:25:DB": "Sony",
                "00:0A:95": "Canon",
                "00:1E:8F": "Canon",
                "00:00:48": "HP",
                "00:30:C1": "HP",
                "00:50:43": "Amazon Ring",
                "7C:C2:C6": "Amazon Ring",
            }
            
            os.makedirs(os.path.dirname(MAC_OUI_DB), exist_ok=True)
            with open(MAC_OUI_DB, 'w') as f:
                json.dump(basic_oui, f, indent=2)
            
            return basic_oui
        
        try:
            with open(MAC_OUI_DB, 'r') as f:
                return json.load(f)
        except:
            return {}
    
    def load_known_devices(self):
        """Load user-defined device information"""
        if not os.path.exists(DEVICE_DB_PATH):
            os.makedirs(os.path.dirname(DEVICE_DB_PATH), exist_ok=True)
            with open(DEVICE_DB_PATH, 'w') as f:
                json.dump({}, f, indent=2)
            return
        
        try:
            with open(DEVICE_DB_PATH, 'r') as f:
                self.devices = json.load(f)
        except:
            self.devices = {}
    
    def save_known_devices(self):
        """Save device registry to file"""
        try:
            with open(DEVICE_DB_PATH, 'w') as f:
                json.dump(self.devices, f, indent=2)
        except Exception as e:
            logging.error(f"Error saving known devices: {e}")
    
    def get_arp_table(self):
        """Get ARP table from system"""
        arp_entries = {}
        try:
            with open('/proc/net/arp', 'r') as f:
                lines = f.readlines()[1:]  # Skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[0]
                        mac = parts[3]
                        if mac != '00:00:00:00:00:00' and mac != '<incomplete>':
                            arp_entries[ip] = mac.upper()
        except Exception as e:
            logging.error(f"Error reading ARP table: {e}")
        
        return arp_entries
    
    def get_hostname(self, ip_address):
        """Resolve hostname for IP address"""
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            return hostname
        except:
            return None
    
    def lookup_vendor(self, mac_address):
        """Lookup vendor from MAC address OUI"""
        if not mac_address:
            return "Unknown"
        
        # Get first 3 octets (OUI)
        oui = ':'.join(mac_address.upper().split(':')[:3])
        
        return self.mac_oui_db.get(oui, "Unknown")
    
    def categorize_device(self, hostname, vendor, open_ports):
        """Categorize device based on available information"""
        hostname_lower = (hostname or "").lower()
        vendor_lower = vendor.lower()
        
        # IoT Devices - Smart Home
        if any(x in vendor_lower for x in ['nest', 'ring', 'echo', 'alexa', 'google home']):
            return "IoT", "Smart Home"
        
        # IoT - Cameras
        if any(x in hostname_lower for x in ['camera', 'cam', 'ipcam', 'hikvision', 'dahua']):
            return "IoT", "Camera"
        
        # IoT - Thermostats/Climate Control
        if any(x in hostname_lower for x in ['thermostat', 'hvac', 'ecobee', 'honeywell']):
            return "IoT", "Thermostat"
        
        # IoT - Smart TVs and streaming devices
        if any(x in hostname_lower for x in ['tv', 'roku', 'firetv', 'chromecast', 'appletv']):
            return "IoT", "Smart TV"
        
        if any(x in vendor_lower for x in ['samsung', 'lg', 'sony', 'vizio']) and 'tv' in hostname_lower:
            return "IoT", "Smart TV"
        
        # IoT - Printers
        if any(x in hostname_lower for x in ['printer', 'canon', 'hp', 'epson', 'brother']):
            return "IoT", "Printer"
        
        # IoT - Smart Lights
        if any(x in hostname_lower for x in ['bulb', 'light', 'philips', 'hue', 'lifx']):
            return "IoT", "Smart Light"
        
        # IoT - Tablets (many Lenovo/Samsung tabs are IoT-like)
        if any(x in hostname_lower for x in ['tab-', 'tablet', 'lenovo-tab', 'samsung-tab', 'kindle-fire']):
            return "IoT", "Tablet Device"
        
        # Network Equipment (Router is the gateway)
        if any(x in vendor_lower for x in ['cisco', 'juniper', 'mikrotik', 'ubiquiti']):
            return "Network", "Router/Switch"
        
        if any(x in hostname_lower for x in ['router', 'gateway', 'modem', 'switch', 'ap', 'access-point', 'sbe1v1k']):
            return "Network", "Router/Switch"
        
        if any(x in vendor_lower for x in ['tp-link', 'netgear', 'd-link', 'belkin', 'linksys']):
            return "Network", "Router/Switch"
        
        # Computers
        if any(x in vendor_lower for x in ['apple', 'dell', 'hp', 'lenovo', 'asus', 'acer']):
            if any(x in hostname_lower for x in ['iphone', 'ipad', 'android']):
                return "Mobile", "Smartphone/Tablet"
            return "Computer", "Desktop/Laptop"
        
        if any(x in hostname_lower for x in ['desktop', 'laptop', 'pc', 'workstation', 'macbook']):
            return "Computer", "Desktop/Laptop"
        
        # Mobile Devices (iPhones/iPads)
        if any(x in hostname_lower for x in ['iphone', 'ipad', 'android', 'samsung-', 'pixel']):
            return "Mobile", "Smartphone/Tablet"
        
        # Servers
        if any(x in hostname_lower for x in ['server', 'nas', 'storage', 'plex', 'ubuntu', 'debian']):
            return "Server", "Server/NAS"
        
        # Raspberry Pi (treat as IoT since it's likely running sensors/automation)
        if 'raspberry pi' in vendor_lower or any(x in hostname_lower for x in ['raspberrypi', 'raspberry', 'pi.lan', 'pi-']):
            return "IoT", "Raspberry Pi"
        
        # Virtual Machines
        if any(x in vendor_lower for x in ['vmware', 'virtualbox', 'qemu']):
            return "Virtual", "Virtual Machine"
        
        return "Unknown", "Unknown"
    
    def update_device(self, ip_address, mac_address=None, hostname=None, traffic_bytes=0):
        """Update or create device entry"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            now = datetime.now().isoformat()
            
            # If no MAC, try to get from ARP
            if not mac_address:
                arp_table = self.get_arp_table()
                mac_address = arp_table.get(ip_address)
            
            # If no hostname provided, try to resolve
            if not hostname:
                hostname = self.get_hostname(ip_address)
            
            # Get vendor from MAC
            vendor = self.lookup_vendor(mac_address) if mac_address else "Unknown"
            
            # Categorize device
            device_type, device_category = self.categorize_device(hostname, vendor, [])
            
            # Check if device exists by IP
            cursor.execute("SELECT * FROM devices WHERE ip_address = ?", (ip_address,))
            existing = cursor.fetchone()
            
            if existing:
                # Update existing device
                cursor.execute("""
                    UPDATE devices 
                    SET mac_address = COALESCE(?, mac_address),
                        hostname = COALESCE(?, hostname),
                        vendor = ?,
                        device_type = ?,
                        device_category = ?,
                        last_seen = ?,
                        total_packets = total_packets + 1,
                        total_bytes = total_bytes + ?
                    WHERE ip_address = ?
                """, (mac_address, hostname, vendor, device_type, device_category, 
                      now, traffic_bytes, ip_address))
            else:
                # Insert new device (with or without MAC)
                cursor.execute("""
                    INSERT INTO devices (
                        mac_address, ip_address, hostname, vendor, 
                        device_type, device_category, first_seen, last_seen,
                        total_packets, total_bytes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                """, (mac_address, ip_address, hostname, vendor, 
                      device_type, device_category, now, now, traffic_bytes))
                
                logging.info(f"✓ New device discovered: {ip_address} {f'({vendor})' if vendor != 'Unknown' else ''} - {device_category}")
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logging.error(f"Error updating device: {e}")
    
    def scan_network(self):
        """Scan network and update device registry"""
        logging.info("Scanning network for devices...")
        
        # Get ARP table
        arp_table = self.get_arp_table()
        
        # Update each device
        for ip, mac in arp_table.items():
            self.update_device(ip, mac)
        
        logging.info(f"✓ Network scan complete. Found {len(arp_table)} devices")
        
        return len(arp_table)
    
    def get_all_devices(self):
        """Get all tracked devices"""
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM devices 
                ORDER BY last_seen DESC
            """)
            
            devices = [dict(row) for row in cursor.fetchall()]
            conn.close()
            
            return devices
        except Exception as e:
            logging.error(f"Error getting devices: {e}")
            return []
    
    def get_device_by_ip(self, ip_address):
        """Get device info by IP address"""
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM devices WHERE ip_address = ?", (ip_address,))
            device = cursor.fetchone()
            conn.close()
            
            return dict(device) if device else None
        except Exception as e:
            logging.error(f"Error getting device: {e}")
            return None
    
    def update_device_security_score(self, mac_address, score):
        """Update device security score"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE devices 
                SET security_score = ? 
                WHERE mac_address = ?
            """, (score, mac_address))
            
            conn.commit()
            conn.close()
        except Exception as e:
            logging.error(f"Error updating security score: {e}")


def main():
    """Main execution"""
    logging.info("=" * 60)
    logging.info("NetGuard Pro - Device Tracker")
    logging.info("=" * 60)
    
    tracker = DeviceTracker()
    
    # Initial network scan
    device_count = tracker.scan_network()
    
    logging.info(f"\n✓ Device tracking initialized")
    logging.info(f"✓ Discovered {device_count} active devices")
    
    # Display devices
    devices = tracker.get_all_devices()
    logging.info(f"\nActive Devices:")
    logging.info("-" * 60)
    for device in devices:
        logging.info(f"  {device['ip_address']:15} | {device['mac_address']:17} | {device['vendor']:20} | {device['device_category']}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

