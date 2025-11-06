#!/usr/bin/env python3
"""
NetGuard Pro - Enhanced Alert System
Provides real-time alerting with severity levels, remediation actions, and notifications
"""

import os
import sqlite3
import logging
import json
import time
import subprocess
from datetime import datetime, timedelta
from typing import List, Dict, Optional

# Configuration
DB_PATH = "/home/jarvis/NetGuard/network.db"
LOG_DIR = "/home/jarvis/NetGuard/logs/system"
ALERT_CONFIG_FILE = "/home/jarvis/NetGuard/config/alert_rules.json"

os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'{LOG_DIR}/alert-system.log'),
        logging.StreamHandler()
    ]
)

# Alert severity levels
SEVERITY_LEVELS = {
    'CRITICAL': {'score': 100, 'color': '#f44336', 'priority': 1},
    'HIGH': {'score': 75, 'color': '#ff9800', 'priority': 2},
    'MEDIUM': {'score': 50, 'color': '#ffeb3b', 'priority': 3},
    'LOW': {'score': 25, 'color': '#4caf50', 'priority': 4},
    'INFO': {'score': 10, 'color': '#2196f3', 'priority': 5}
}

class EnhancedAlertSystem:
    def __init__(self):
        self.db_path = DB_PATH
        self.init_database()
        self.load_alert_rules()
    
    def init_database(self):
        """Initialize the alerts database table"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create alerts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT UNIQUE NOT NULL,
                severity TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                source_ip TEXT,
                dest_ip TEXT,
                source_device TEXT,
                affected_devices TEXT,
                threat_indicators TEXT,
                remediation_steps TEXT,
                auto_remediation_available INTEGER DEFAULT 0,
                auto_remediation_command TEXT,
                status TEXT DEFAULT 'active',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                resolved_at DATETIME,
                resolved_by TEXT,
                false_positive INTEGER DEFAULT 0,
                recurrence_count INTEGER DEFAULT 1,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create alert history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alert_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT NOT NULL,
                action TEXT NOT NULL,
                action_by TEXT,
                notes TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create alert rules table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alert_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT UNIQUE NOT NULL,
                rule_type TEXT NOT NULL,
                condition TEXT NOT NULL,
                threshold_value REAL,
                severity TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                auto_remediation INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        conn.close()
        logging.info("✓ Alert system database initialized")
    
    def load_alert_rules(self):
        """Load alert rules from configuration"""
        default_rules = {
            "rules": [
                {
                    "name": "Port_Scan_Detection",
                    "type": "behavioral",
                    "condition": "connection_attempts > threshold in timeframe",
                    "threshold": 20,
                    "timeframe_seconds": 60,
                    "severity": "HIGH",
                    "auto_remediation": True
                },
                {
                    "name": "Brute_Force_Attack",
                    "type": "authentication",
                    "condition": "failed_login_attempts > threshold",
                    "threshold": 5,
                    "timeframe_seconds": 300,
                    "severity": "CRITICAL",
                    "auto_remediation": True
                },
                {
                    "name": "Unusual_Outbound_Traffic",
                    "type": "traffic",
                    "condition": "outbound_bytes > threshold",
                    "threshold": 1000000000,  # 1GB
                    "timeframe_seconds": 3600,
                    "severity": "MEDIUM",
                    "auto_remediation": False
                },
                {
                    "name": "IoT_Device_Compromise",
                    "type": "iot",
                    "condition": "iot_unexpected_connection",
                    "severity": "CRITICAL",
                    "auto_remediation": True
                },
                {
                    "name": "Malware_C2_Communication",
                    "type": "malware",
                    "condition": "known_c2_ip_contacted",
                    "severity": "CRITICAL",
                    "auto_remediation": True
                },
                {
                    "name": "DNS_Tunneling",
                    "type": "exfiltration",
                    "condition": "dns_query_length > threshold or dns_query_rate > threshold",
                    "threshold": 63,
                    "severity": "HIGH",
                    "auto_remediation": False
                }
            ]
        }
        
        # Create default config if not exists
        if not os.path.exists(ALERT_CONFIG_FILE):
            os.makedirs(os.path.dirname(ALERT_CONFIG_FILE), exist_ok=True)
            with open(ALERT_CONFIG_FILE, 'w') as f:
                json.dump(default_rules, f, indent=2)
            logging.info(f"✓ Created default alert rules: {ALERT_CONFIG_FILE}")
        
        with open(ALERT_CONFIG_FILE, 'r') as f:
            self.rules = json.load(f)['rules']
    
    def create_alert(self, severity: str, alert_type: str, title: str, 
                     description: str, source_ip: Optional[str] = None,
                     dest_ip: Optional[str] = None, affected_devices: Optional[List[str]] = None,
                     threat_indicators: Optional[List[str]] = None,
                     remediation_steps: Optional[List[str]] = None,
                     auto_remediation_cmd: Optional[str] = None) -> str:
        """Create a new security alert"""
        
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Generate unique alert ID
        alert_id = f"ALERT-{datetime.now().strftime('%Y%m%d%H%M%S')}-{alert_type[:4].upper()}"
        
        # Check if similar alert exists (deduplication)
        cursor.execute("""
            SELECT id, alert_id, recurrence_count FROM security_alerts
            WHERE alert_type = ? AND source_ip = ? AND status = 'active'
            AND created_at > datetime('now', '-1 hour')
        """, (alert_type, source_ip))
        
        existing = cursor.fetchone()
        
        if existing:
            # Update recurrence count
            cursor.execute("""
                UPDATE security_alerts
                SET recurrence_count = recurrence_count + 1,
                    last_seen = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (existing['id'],))
            alert_id = existing['alert_id']
            logging.info(f"Updated existing alert {alert_id} (recurrence: {existing['recurrence_count'] + 1})")
        else:
            # Create new alert
            cursor.execute("""
                INSERT INTO security_alerts (
                    alert_id, severity, alert_type, title, description,
                    source_ip, dest_ip, affected_devices, threat_indicators,
                    remediation_steps, auto_remediation_available,
                    auto_remediation_command
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert_id, severity, alert_type, title, description,
                source_ip, dest_ip,
                json.dumps(affected_devices) if affected_devices else None,
                json.dumps(threat_indicators) if threat_indicators else None,
                json.dumps(remediation_steps) if remediation_steps else None,
                1 if auto_remediation_cmd else 0,
                auto_remediation_cmd
            ))
            
            # Log to alert history
            cursor.execute("""
                INSERT INTO alert_history (alert_id, action, action_by, notes)
                VALUES (?, 'created', 'system', ?)
            """, (alert_id, f"Alert created: {title}"))
            
            logging.warning(f"🚨 NEW ALERT [{severity}]: {title} ({alert_id})")
        
        conn.commit()
        conn.close()
        
        return alert_id
    
    def resolve_alert(self, alert_id: str, resolved_by: str = 'user', notes: Optional[str] = None):
        """Mark an alert as resolved"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE security_alerts
            SET status = 'resolved',
                resolved_at = CURRENT_TIMESTAMP,
                resolved_by = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE alert_id = ?
        """, (resolved_by, alert_id))
        
        cursor.execute("""
            INSERT INTO alert_history (alert_id, action, action_by, notes)
            VALUES (?, 'resolved', ?, ?)
        """, (alert_id, resolved_by, notes or 'Alert resolved'))
        
        conn.commit()
        conn.close()
        logging.info(f"✓ Alert {alert_id} resolved by {resolved_by}")
    
    def execute_auto_remediation(self, alert_id: str) -> bool:
        """Execute automatic remediation for an alert"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT alert_id, title, auto_remediation_command, source_ip
            FROM security_alerts
            WHERE alert_id = ? AND auto_remediation_available = 1
        """, (alert_id,))
        
        alert = cursor.fetchone()
        
        if not alert or not alert['auto_remediation_command']:
            logging.error(f"No auto-remediation available for {alert_id}")
            return False
        
        try:
            # Execute remediation command
            cmd = alert['auto_remediation_command']
            logging.info(f"Executing auto-remediation for {alert_id}: {cmd}")
            
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=30
            )
            
            success = result.returncode == 0
            
            # Log action
            cursor.execute("""
                INSERT INTO alert_history (alert_id, action, action_by, notes)
                VALUES (?, 'auto_remediation', 'system', ?)
            """, (alert_id, f"Command executed: {cmd}\nResult: {result.stdout or result.stderr}"))
            
            if success:
                # Mark as resolved
                cursor.execute("""
                    UPDATE security_alerts
                    SET status = 'resolved',
                        resolved_at = CURRENT_TIMESTAMP,
                        resolved_by = 'auto_remediation',
                        updated_at = CURRENT_TIMESTAMP
                    WHERE alert_id = ?
                """, (alert_id,))
                logging.info(f"✓ Auto-remediation successful for {alert_id}")
            else:
                logging.error(f"✗ Auto-remediation failed for {alert_id}: {result.stderr}")
            
            conn.commit()
            return success
            
        except Exception as e:
            logging.error(f"Error executing auto-remediation for {alert_id}: {e}")
            cursor.execute("""
                INSERT INTO alert_history (alert_id, action, action_by, notes)
                VALUES (?, 'auto_remediation_failed', 'system', ?)
            """, (alert_id, str(e)))
            conn.commit()
            return False
        finally:
            conn.close()
    
    def mark_false_positive(self, alert_id: str, marked_by: str = 'user'):
        """Mark an alert as a false positive"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE security_alerts
            SET false_positive = 1,
                status = 'false_positive',
                updated_at = CURRENT_TIMESTAMP
            WHERE alert_id = ?
        """, (alert_id,))
        
        cursor.execute("""
            INSERT INTO alert_history (alert_id, action, action_by, notes)
            VALUES (?, 'marked_false_positive', ?, 'Alert marked as false positive')
        """, (alert_id, marked_by))
        
        conn.commit()
        conn.close()
        logging.info(f"Alert {alert_id} marked as false positive")
    
    def get_active_alerts(self, severity: Optional[str] = None) -> List[Dict]:
        """Get all active alerts"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        if severity:
            cursor.execute("""
                SELECT * FROM security_alerts
                WHERE status = 'active' AND severity = ?
                ORDER BY created_at DESC
            """, (severity,))
        else:
            cursor.execute("""
                SELECT * FROM security_alerts
                WHERE status = 'active'
                ORDER BY 
                    CASE severity
                        WHEN 'CRITICAL' THEN 1
                        WHEN 'HIGH' THEN 2
                        WHEN 'MEDIUM' THEN 3
                        WHEN 'LOW' THEN 4
                        ELSE 5
                    END,
                    created_at DESC
            """)
        
        alerts = []
        for row in cursor.fetchall():
            alert = dict(row)
            # Parse JSON fields
            if alert['affected_devices']:
                alert['affected_devices'] = json.loads(alert['affected_devices'])
            if alert['threat_indicators']:
                alert['threat_indicators'] = json.loads(alert['threat_indicators'])
            if alert['remediation_steps']:
                alert['remediation_steps'] = json.loads(alert['remediation_steps'])
            alerts.append(alert)
        
        conn.close()
        return alerts
    
    def get_alert_statistics(self) -> Dict:
        """Get alert statistics"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Count by severity
        cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM security_alerts
            WHERE status = 'active'
            GROUP BY severity
        """)
        severity_counts = {row['severity']: row['count'] for row in cursor.fetchall()}
        
        # Count by status
        cursor.execute("""
            SELECT status, COUNT(*) as count
            FROM security_alerts
            GROUP BY status
        """)
        status_counts = {row['status']: row['count'] for row in cursor.fetchall()}
        
        # Recent alerts (last 24 hours)
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM security_alerts
            WHERE created_at > datetime('now', '-24 hours')
        """)
        recent_count = cursor.fetchone()['count']
        
        # Auto-remediation success rate
        cursor.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN action = 'auto_remediation' THEN 1 ELSE 0 END) as success,
                SUM(CASE WHEN action = 'auto_remediation_failed' THEN 1 ELSE 0 END) as failed
            FROM alert_history
            WHERE action IN ('auto_remediation', 'auto_remediation_failed')
        """)
        remediation_stats = dict(cursor.fetchone())
        
        conn.close()
        
        return {
            'severity_counts': severity_counts,
            'status_counts': status_counts,
            'recent_24h': recent_count,
            'auto_remediation': remediation_stats
        }
    
    def scan_for_threats(self):
        """Scan recent data for threats and generate alerts"""
        logging.info("Scanning for security threats...")
        
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # 1. Check for port scanning
        cursor.execute("""
            SELECT src_ip, COUNT(DISTINCT dest_port) as port_count
            FROM (
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name LIKE 'tcpdump_%'
                AND name NOT LIKE '%_template'
                ORDER BY name DESC LIMIT 1
            ) AS latest_table,
            (SELECT * FROM tcpdump ORDER BY timestamp DESC LIMIT 1000)
            WHERE timestamp > datetime('now', '-5 minutes')
            AND src_ip LIKE '192.168.%'
            GROUP BY src_ip
            HAVING port_count > 20
        """)
        
        for row in cursor.fetchall():
            self.create_alert(
                severity='HIGH',
                alert_type='port_scan',
                title=f'Port Scan Detected from {row["src_ip"]}',
                description=f'Device scanned {row["port_count"]} ports in the last 5 minutes',
                source_ip=row['src_ip'],
                threat_indicators=[f'{row["port_count"]} ports scanned'],
                remediation_steps=[
                    'Investigate the device behavior',
                    'Check if device is compromised',
                    'Consider network isolation',
                    'Block scanning IP if unauthorized'
                ],
                auto_remediation_cmd=f'sudo iptables -A INPUT -s {row["src_ip"]} -j DROP'
            )
        
        # 2. Check for IoT vulnerabilities
        cursor.execute("""
            SELECT device_ip, device_mac, COUNT(*) as vuln_count,
                   GROUP_CONCAT(vulnerability_type) as vulns
            FROM iot_vulnerabilities
            WHERE resolved = 0 AND severity IN ('CRITICAL', 'HIGH')
            GROUP BY device_ip
            HAVING vuln_count >= 2
        """)
        
        for row in cursor.fetchall():
            self.create_alert(
                severity='CRITICAL',
                alert_type='iot_compromise',
                title=f'Multiple Vulnerabilities on IoT Device {row["device_ip"]}',
                description=f'Found {row["vuln_count"]} critical/high vulnerabilities',
                source_ip=row['device_ip'],
                threat_indicators=row['vulns'].split(',') if row['vulns'] else [],
                remediation_steps=[
                    'Update device firmware immediately',
                    'Change default credentials',
                    'Isolate device to IoT VLAN',
                    'Disable unnecessary services',
                    'Enable encryption if available'
                ]
            )
        
        # 3. Check for suspicious outbound connections
        cursor.execute("""
            SELECT src_ip, COUNT(*) as conn_count, 
                   GROUP_CONCAT(DISTINCT dest_ip) as destinations
            FROM (
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name LIKE 'tcpdump_%'
                AND name NOT LIKE '%_template'
                ORDER BY name DESC LIMIT 1
            ) AS latest_table,
            (SELECT * FROM tcpdump ORDER BY timestamp DESC LIMIT 5000)
            WHERE timestamp > datetime('now', '-5 minutes')
            AND src_ip LIKE '192.168.%'
            AND dest_ip NOT LIKE '192.168.%'
            AND dest_ip NOT LIKE '10.%'
            AND dest_ip NOT LIKE '172.%'
            GROUP BY src_ip
            HAVING conn_count > 50
        """)
        
        for row in cursor.fetchall():
            self.create_alert(
                severity='MEDIUM',
                alert_type='unusual_traffic',
                title=f'Unusual Outbound Traffic from {row["src_ip"]}',
                description=f'Device made {row["conn_count"]} external connections in 5 minutes',
                source_ip=row['src_ip'],
                threat_indicators=[f'{row["conn_count"]} connections to external IPs'],
                remediation_steps=[
                    'Review device applications',
                    'Check for malware or compromised services',
                    'Verify connections are legitimate',
                    'Monitor continued behavior'
                ]
            )
        
        conn.close()
        logging.info("✓ Threat scan completed")

def main():
    """Main loop for alert monitoring"""
    alert_system = EnhancedAlertSystem()
    
    logging.info("============================================================")
    logging.info("NetGuard Pro - Enhanced Alert System")
    logging.info("============================================================")
    logging.info("Monitoring for security threats...")
    
    cycle = 0
    while True:
        cycle += 1
        logging.info(f"\n--- Alert Scan Cycle {cycle} ---")
        
        try:
            # Scan for new threats
            alert_system.scan_for_threats()
            
            # Get statistics
            stats = alert_system.get_alert_statistics()
            logging.info(f"Active alerts: {stats['severity_counts']}")
            logging.info(f"Recent 24h: {stats['recent_24h']} alerts")
            
        except Exception as e:
            logging.error(f"Error in alert cycle: {e}")
        
        # Wait 5 minutes
        time.sleep(300)

if __name__ == "__main__":
    main()

