#!/usr/bin/env python3
"""
NetGuard Pro - IoT Security Scanner
Scan IoT devices for security vulnerabilities and suspicious behavior
"""

import os
import sys
import json
import sqlite3
import logging
import socket
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict

# Configuration
DB_PATH = "/home/jarvis/NetGuard/network.db"
IOT_SIGNATURES = "/home/jarvis/NetGuard/config/iot_signatures.json"
LOG_FILE = "/home/jarvis/NetGuard/logs/system/iot-security-scanner.log"
SCAN_INTERVAL = 300  # 5 minutes

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

class IoTSecurityScanner:
    def __init__(self):
        self.signatures = self.load_signatures()
        self.vulnerabilities = []
        self.init_vulnerability_table()
    
    def init_vulnerability_table(self):
        """Initialize vulnerability tracking table"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS iot_vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_ip TEXT,
                    device_mac TEXT,
                    device_type TEXT,
                    vulnerability_type TEXT,
                    severity TEXT,
                    description TEXT,
                    detected_at DATETIME,
                    resolved INTEGER DEFAULT 0,
                    resolved_at DATETIME,
                    recommendation TEXT
                )
            """)
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vuln_ip ON iot_vulnerabilities(device_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vuln_resolved ON iot_vulnerabilities(resolved)")
            
            conn.commit()
            conn.close()
            logging.info("✓ Vulnerability tracking table initialized")
        except Exception as e:
            logging.error(f"Error initializing vulnerability table: {e}")
    
    def load_signatures(self):
        """Load IoT device signatures"""
        try:
            with open(IOT_SIGNATURES, 'r') as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Error loading IoT signatures: {e}")
            return {}
    
    def get_iot_devices(self):
        """Get all IoT devices from device tracker"""
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM devices 
                WHERE device_type = 'IoT' 
                AND last_seen > datetime('now', '-1 hour')
            """)
            
            devices = [dict(row) for row in cursor.fetchall()]
            conn.close()
            
            return devices
        except Exception as e:
            logging.error(f"Error getting IoT devices: {e}")
            return []
    
    def check_open_ports(self, ip_address, ports_to_check):
        """Check for open ports on device"""
        open_ports = []
        
        for port in ports_to_check:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            
            try:
                result = sock.connect_ex((ip_address, port))
                if result == 0:
                    open_ports.append(port)
            except:
                pass
            finally:
                sock.close()
        
        return open_ports
    
    def check_telnet_vulnerability(self, device):
        """Check if device has open telnet ports"""
        telnet_ports = self.signatures.get('suspicious_ports', {}).get('telnet', [23, 2323])
        open_telnet = self.check_open_ports(device['ip_address'], telnet_ports)
        
        if open_telnet:
            self.record_vulnerability(
                device=device,
                vuln_type="open_telnet",
                severity="HIGH",
                description=f"Telnet port(s) {open_telnet} open on IoT device. This is a major security risk.",
                recommendation="Disable telnet immediately. Use SSH with key authentication if remote access is needed."
            )
            return True
        
        return False
    
    def check_vulnerable_services(self, device):
        """Check for commonly exploited ports"""
        vulnerable_ports = self.signatures.get('suspicious_ports', {}).get('vulnerable_services', [])
        open_vulnerable = self.check_open_ports(device['ip_address'], vulnerable_ports[:10])  # Check first 10 to save time
        
        if open_vulnerable:
            port_services = {
                21: "FTP", 69: "TFTP", 161: "SNMP", 445: "SMB", 
                1433: "MS-SQL", 3306: "MySQL", 3389: "RDP", 
                5432: "PostgreSQL", 5900: "VNC", 8291: "MikroTik"
            }
            
            service_names = [f"{port}({port_services.get(port, 'Unknown')})" for port in open_vulnerable]
            
            self.record_vulnerability(
                device=device,
                vuln_type="vulnerable_services",
                severity="MEDIUM",
                description=f"Potentially vulnerable services exposed: {', '.join(service_names)}",
                recommendation="Review if these services need to be exposed. Implement firewall rules to restrict access."
            )
            return True
        
        return False
    
    def check_suspicious_connections(self, device):
        """Check for suspicious outbound connections"""
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Check recent connections from this device
            # Look for connections to suspicious ports
            suspicious_ports = (
                self.signatures.get('suspicious_ports', {}).get('c2_common', []) +
                self.signatures.get('suspicious_ports', {}).get('mining_pools', [])
            )
            
            # Get latest tcpdump/tshark table
            cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND (name LIKE 'tcpdump_%' OR name LIKE 'tshark_%')
                AND name NOT LIKE '%_template'
                ORDER BY name DESC LIMIT 1
            """)
            
            table_result = cursor.fetchone()
            if table_result:
                table_name = table_result['name']
                
                # Check for connections to suspicious ports
                cursor.execute(f"""
                    SELECT dest_ip, dest_port, COUNT(*) as count
                    FROM {table_name}
                    WHERE src_ip = ?
                    AND dest_port IN ({','.join(map(str, suspicious_ports))})
                    GROUP BY dest_ip, dest_port
                """, (device['ip_address'],))
                
                suspicious_conns = cursor.fetchall()
                
                if suspicious_conns:
                    conn_details = [f"{row['dest_ip']}:{row['dest_port']}" for row in suspicious_conns]
                    
                    self.record_vulnerability(
                        device=device,
                        vuln_type="suspicious_connections",
                        severity="HIGH",
                        description=f"Device connecting to suspicious ports: {', '.join(conn_details)}",
                        recommendation="Investigate these connections. Block if confirmed malicious. Device may be compromised."
                    )
            
            conn.close()
            
        except Exception as e:
            logging.error(f"Error checking suspicious connections: {e}")
    
    def check_excessive_traffic(self, device):
        """Check for unusual traffic patterns"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Check if device has excessive traffic for its type
            device_category = device.get('device_category', '').lower()
            
            # Get expected bandwidth patterns
            expected_patterns = {
                'smart light': 100000,      # 100KB
                'thermostat': 500000,       # 500KB
                'smart plug': 200000,       # 200KB
                'camera': 100000000,        # 100MB (high is normal)
                'smart tv': 500000000,      # 500MB (high is normal)
                'smart speaker': 10000000,  # 10MB
            }
            
            threshold = expected_patterns.get(device_category, 50000000)  # Default 50MB
            
            if device.get('total_bytes', 0) > threshold:
                # For low-bandwidth devices, this is suspicious
                if device_category in ['smart light', 'thermostat', 'smart plug']:
                    self.record_vulnerability(
                        device=device,
                        vuln_type="excessive_traffic",
                        severity="MEDIUM",
                        description=f"Unusual traffic volume for {device_category}: {device['total_bytes']} bytes",
                        recommendation="Investigate device behavior. May indicate data exfiltration or botnet activity."
                    )
            
            conn.close()
            
        except Exception as e:
            logging.error(f"Error checking traffic patterns: {e}")
    
    def check_default_credentials(self, device):
        """Check for common default credential vulnerabilities"""
        # This is a passive check based on device type
        device_category = device.get('device_category', '').lower()
        vendor = device.get('vendor', '').lower()
        
        # Known vendors with default credential issues
        risky_vendors = [
            'hikvision', 'dahua', 'foscam', 'tp-link', 'netgear', 'd-link'
        ]
        
        if any(v in vendor for v in risky_vendors):
            self.record_vulnerability(
                device=device,
                vuln_type="default_credentials_risk",
                severity="MEDIUM",
                description=f"Device from vendor with known default credential issues: {vendor}",
                recommendation="Ensure default password has been changed. Check manufacturer's security advisories."
            )
    
    def check_firmware_updates(self, device):
        """Check if device firmware might be outdated"""
        # This is a general recommendation based on device age
        try:
            first_seen = datetime.fromisoformat(device.get('first_seen', ''))
            age_days = (datetime.now() - first_seen).days
            
            if age_days > 90:  # Device seen for more than 3 months
                self.record_vulnerability(
                    device=device,
                    vuln_type="firmware_update_needed",
                    severity="LOW",
                    description=f"Device has been active for {age_days} days. Firmware may be outdated.",
                    recommendation="Check manufacturer website for firmware updates. Enable auto-update if available."
                )
        except:
            pass
    
    def record_vulnerability(self, device, vuln_type, severity, description, recommendation):
        """Record discovered vulnerability"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Check if this vulnerability was already recorded recently
            cursor.execute("""
                SELECT id FROM iot_vulnerabilities
                WHERE device_ip = ? 
                AND vulnerability_type = ?
                AND resolved = 0
                AND detected_at > datetime('now', '-24 hours')
            """, (device['ip_address'], vuln_type))
            
            existing = cursor.fetchone()
            
            if not existing:
                # Insert new vulnerability
                cursor.execute("""
                    INSERT INTO iot_vulnerabilities (
                        device_ip, device_mac, device_type, vulnerability_type,
                        severity, description, detected_at, recommendation
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    device['ip_address'],
                    device.get('mac_address'),
                    device.get('device_category'),
                    vuln_type,
                    severity,
                    description,
                    datetime.now().isoformat(),
                    recommendation
                ))
                
                conn.commit()
                logging.warning(f"⚠️  {severity}: {description} ({device['ip_address']})")
            
            conn.close()
            
        except Exception as e:
            logging.error(f"Error recording vulnerability: {e}")
    
    def scan_device(self, device):
        """Run all security checks on a device"""
        logging.info(f"Scanning device: {device['ip_address']} ({device.get('device_category', 'Unknown')})")
        
        # Run all checks
        self.check_telnet_vulnerability(device)
        self.check_vulnerable_services(device)
        self.check_suspicious_connections(device)
        self.check_excessive_traffic(device)
        self.check_default_credentials(device)
        self.check_firmware_updates(device)
    
    def scan_all_devices(self):
        """Scan all IoT devices"""
        devices = self.get_iot_devices()
        
        if not devices:
            logging.info("No IoT devices found to scan")
            return
        
        logging.info(f"Starting security scan on {len(devices)} IoT devices...")
        
        for device in devices:
            try:
                self.scan_device(device)
            except Exception as e:
                logging.error(f"Error scanning device {device['ip_address']}: {e}")
        
        logging.info("✓ IoT security scan complete")
    
    def get_vulnerability_summary(self):
        """Get summary of current vulnerabilities"""
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT severity, COUNT(*) as count
                FROM iot_vulnerabilities
                WHERE resolved = 0
                GROUP BY severity
            """)
            
            summary = {row['severity']: row['count'] for row in cursor.fetchall()}
            conn.close()
            
            return summary
        except Exception as e:
            logging.error(f"Error getting vulnerability summary: {e}")
            return {}


def main():
    """Main execution"""
    logging.info("=" * 60)
    logging.info("NetGuard Pro - IoT Security Scanner")
    logging.info("=" * 60)
    
    scanner = IoTSecurityScanner()
    scanner.scan_all_devices()
    
    # Print summary
    summary = scanner.get_vulnerability_summary()
    if summary:
        logging.info("\nVulnerability Summary:")
        logging.info("-" * 60)
        for severity, count in summary.items():
            logging.info(f"  {severity}: {count}")
    else:
        logging.info("\n✓ No active vulnerabilities detected")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

