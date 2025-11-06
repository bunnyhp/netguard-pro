#!/usr/bin/env python3
"""
NetGuard Pro - Enhanced IoT Security Scanner
Advanced IoT device security monitoring with real-time threat detection,
behavioral analysis, communication pattern monitoring, and vulnerability assessment
"""

import os
import sys
import json
import sqlite3
import logging
import socket
import subprocess
import time
import re
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import hashlib

# Configuration
DB_PATH = "/home/jarvis/NetGuard/network.db"
LOG_FILE = "/home/jarvis/NetGuard/logs/system/enhanced-iot-scanner.log"
SCAN_INTERVAL = 300  # 5 minutes
REAL_TIME_INTERVAL = 60  # 1 minute for real-time monitoring

# Setup logging
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

class EnhancedIoTSecurityScanner:
    def __init__(self):
        self.init_database()
        self.device_signatures = self.load_device_signatures()
        self.threat_indicators = self.load_threat_indicators()
        self.communication_patterns = defaultdict(list)
        self.behavioral_baselines = {}
        
    def init_database(self):
        """Initialize all required database tables"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # IoT vulnerabilities table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS iot_vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_ip TEXT NOT NULL,
                device_mac TEXT,
                device_type TEXT,
                vulnerability_type TEXT NOT NULL,
                severity INTEGER NOT NULL,  -- 1=CRITICAL, 2=HIGH, 3=MEDIUM, 4=LOW
                description TEXT NOT NULL,
                detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                resolved INTEGER DEFAULT 0,
                resolved_at DATETIME,
                recommendation TEXT,
                auto_fixed INTEGER DEFAULT 0,
                threat_indicators TEXT,  -- JSON array of indicators
                remediation_applied TEXT
            )
        """)
        
        # Real-time communication monitoring
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS iot_communications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_ip TEXT NOT NULL,
                device_mac TEXT,
                dest_ip TEXT,
                dest_domain TEXT,
                protocol TEXT,
                port INTEGER,
                data_size INTEGER,
                packet_count INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                risk_level INTEGER DEFAULT 0,  -- 0=safe, 1=low, 2=medium, 3=high, 4=critical
                is_suspicious INTEGER DEFAULT 0,
                analysis_notes TEXT
            )
        """)
        
        # Behavioral analysis data
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS iot_behavioral_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_ip TEXT NOT NULL,
                device_mac TEXT,
                activity_type TEXT NOT NULL,  -- normal, suspicious, anomalous
                activity_score REAL NOT NULL,  -- 0-100, higher = more suspicious
                data_points TEXT,  -- JSON array of behavioral metrics
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                baseline_deviation REAL DEFAULT 0.0
            )
        """)
        
        # Domain communication patterns
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS iot_domain_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_ip TEXT NOT NULL,
                domain TEXT NOT NULL,
                frequency INTEGER DEFAULT 1,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                risk_level INTEGER DEFAULT 0,
                is_whitelisted INTEGER DEFAULT 0,
                analysis_notes TEXT
            )
        """)
        
        # Security alerts specific to IoT
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS iot_security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT UNIQUE NOT NULL,
                device_ip TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                threat_indicators TEXT,  -- JSON array
                remediation_steps TEXT,  -- JSON array
                auto_remediation_cmd TEXT,
                status TEXT DEFAULT 'active',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                resolved_at DATETIME,
                false_positive INTEGER DEFAULT 0
            )
        """)
        
        # Device security scores
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS iot_security_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_ip TEXT UNIQUE NOT NULL,
                device_mac TEXT,
                overall_score INTEGER NOT NULL,  -- 0-100
                vulnerability_score INTEGER NOT NULL,
                communication_score INTEGER NOT NULL,
                behavioral_score INTEGER NOT NULL,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                score_history TEXT  -- JSON array of historical scores
            )
        """)
        
        # Create indexes for performance
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_iot_vuln_ip ON iot_vulnerabilities(device_ip)",
            "CREATE INDEX IF NOT EXISTS idx_iot_vuln_resolved ON iot_vulnerabilities(resolved)",
            "CREATE INDEX IF NOT EXISTS idx_iot_comm_ip ON iot_communications(device_ip)",
            "CREATE INDEX IF NOT EXISTS idx_iot_comm_time ON iot_communications(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_iot_behavior_ip ON iot_behavioral_data(device_ip)",
            "CREATE INDEX IF NOT EXISTS idx_iot_domain_ip ON iot_domain_patterns(device_ip)",
            "CREATE INDEX IF NOT EXISTS idx_iot_alerts_ip ON iot_security_alerts(device_ip)",
            "CREATE INDEX IF NOT EXISTS idx_iot_scores_ip ON iot_security_scores(device_ip)"
        ]
        
        for index in indexes:
            cursor.execute(index)
        
        conn.commit()
        conn.close()
        logging.info("✓ Enhanced IoT security database tables initialized")
    
    def load_device_signatures(self):
        """Load IoT device signatures and known vulnerabilities"""
        return {
            "cameras": {
                "ports": [80, 443, 554, 8080, 8081, 8000, 8001],
                "user_agents": ["camera", "ipcam", "dvr", "nvr"],
                "vulnerabilities": ["default_credentials", "unencrypted_stream", "remote_access"]
            },
            "smart_tv": {
                "ports": [80, 443, 9080, 9081, 7001, 7002],
                "user_agents": ["smarttv", "webos", "tizen", "androidtv"],
                "vulnerabilities": ["firmware_outdated", "unencrypted_data", "telemetry"]
            },
            "smart_speakers": {
                "ports": [80, 443, 8443, 8888],
                "user_agents": ["alexa", "google", "assistant", "speaker"],
                "vulnerabilities": ["voice_eavesdropping", "data_collection", "remote_control"]
            },
            "smart_thermostats": {
                "ports": [80, 443, 8080],
                "user_agents": ["thermostat", "nest", "honeywell", "ecobee"],
                "vulnerabilities": ["temperature_manipulation", "schedule_tampering", "data_theft"]
            },
            "smart_plugs": {
                "ports": [80, 443, 8080],
                "user_agents": ["smartplug", "wemo", "tp-link", "kasa"],
                "vulnerabilities": ["power_manipulation", "network_access", "firmware_hijack"]
            },
            "iot_generic": {
                "ports": [80, 443, 8080, 8443, 8888],
                "user_agents": ["iot", "device", "sensor", "controller"],
                "vulnerabilities": ["default_passwords", "unencrypted_comm", "firmware_vuln"]
            }
        }
    
    def load_threat_indicators(self):
        """Load known threat indicators and attack patterns"""
        return {
            "malware_c2": {
                "domains": ["malware.com", "c2server.net", "botnet.org"],
                "ports": [6667, 8080, 8443, 9001],
                "patterns": ["beacon", "command", "control"]
            },
            "data_exfiltration": {
                "domains": ["dropbox.com", "drive.google.com", "onedrive.live.com"],
                "ports": [443, 80],
                "patterns": ["large_upload", "encrypted_data", "scheduled_upload"]
            },
            "lateral_movement": {
                "domains": [],
                "ports": [22, 23, 135, 139, 445, 3389],
                "patterns": ["multiple_connections", "privilege_escalation", "service_enumeration"]
            },
            "crypto_mining": {
                "domains": ["pool.minexmr.com", "stratum+tcp://"],
                "ports": [4444, 8080, 9999],
                "patterns": ["mining_pool", "stratum_protocol", "high_cpu"]
            }
        }
    
    def get_iot_devices(self):
        """Get all IoT devices from the devices table"""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get devices that are likely IoT based on various criteria
        cursor.execute("""
            SELECT DISTINCT 
                d.*,
                COUNT(v.id) as vulnerability_count,
                MAX(v.severity) as max_vulnerability_severity,
                COALESCE(s.overall_score, 50) as security_score
            FROM devices d
            LEFT JOIN iot_vulnerabilities v ON d.ip_address = v.device_ip AND v.resolved = 0
            LEFT JOIN iot_security_scores s ON d.ip_address = s.device_ip
            WHERE (
                d.device_type = 'IoT' OR
                d.device_category LIKE '%camera%' OR
                d.device_category LIKE '%tv%' OR
                d.device_category LIKE '%speaker%' OR
                d.device_category LIKE '%thermostat%' OR
                d.device_category LIKE '%plug%' OR
                d.device_category LIKE '%sensor%' OR
                d.vendor IN ('Amazon', 'Google', 'Samsung', 'LG', 'Sony', 'TP-Link', 'Belkin', 'Netgear', 'D-Link')
            )
            AND d.last_seen > datetime('now', '-24 hours')
            GROUP BY d.ip_address
        """)
        
        devices = []
        for row in cursor.fetchall():
            device = dict(row)
            device['vulnerabilities'] = {
                'count': device['vulnerability_count'],
                'max_severity': device['max_vulnerability_severity'] or 0
            }
            devices.append(device)
        
        conn.close()
        return devices
    
    def analyze_device_vulnerabilities(self, device):
        """Analyze device for security vulnerabilities"""
        vulnerabilities = []
        device_ip = device['ip_address']
        device_type = device.get('device_category', 'unknown').lower()
        
        # 1. Check for open ports
        open_ports = self.scan_device_ports(device_ip)
        if open_ports:
            # Check for risky open ports
            risky_ports = [21, 23, 135, 139, 445, 1433, 3389, 5432, 3306]
            for port in open_ports:
                if port in risky_ports:
                    vulnerabilities.append({
                        'type': 'risky_open_port',
                        'severity': 3,  # MEDIUM
                        'description': f'Risky port {port} is open',
                        'recommendation': f'Close port {port} if not needed'
                    })
        
        # 2. Check for default credentials (simulation)
        if self.check_default_credentials(device_ip):
            vulnerabilities.append({
                'type': 'default_credentials',
                'severity': 2,  # HIGH
                'description': 'Device may be using default credentials',
                'recommendation': 'Change default username/password immediately'
            })
        
        # 3. Check for unencrypted communication
        unencrypted_traffic = self.check_unencrypted_communication(device_ip)
        if unencrypted_traffic:
            vulnerabilities.append({
                'type': 'unencrypted_communication',
                'severity': 3,  # MEDIUM
                'description': 'Device using unencrypted communication',
                'recommendation': 'Enable encryption for all communications'
            })
        
        # 4. Check for suspicious outbound connections
        suspicious_connections = self.check_suspicious_connections(device_ip)
        if suspicious_connections:
            vulnerabilities.append({
                'type': 'suspicious_connections',
                'severity': 2,  # HIGH
                'description': 'Device making suspicious outbound connections',
                'recommendation': 'Investigate and block suspicious connections'
            })
        
        # 5. Device-specific vulnerability checks
        device_vulns = self.check_device_specific_vulnerabilities(device, device_type)
        vulnerabilities.extend(device_vulns)
        
        return vulnerabilities
    
    def scan_device_ports(self, device_ip, timeout=2):
        """Scan device for open ports"""
        open_ports = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((device_ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                continue
        
        return open_ports
    
    def check_default_credentials(self, device_ip):
        """Check for default credentials (simulation based on device behavior)"""
        # This is a simulation - in real implementation, you'd use tools like hydra, medusa, etc.
        # For now, we'll check if device has common default ports open
        open_ports = self.scan_device_ports(device_ip)
        risky_default_ports = [80, 8080, 8443, 8888]  # Common default web interfaces
        
        return any(port in open_ports for port in risky_default_ports)
    
    def check_unencrypted_communication(self, device_ip):
        """Check for unencrypted communication patterns"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check for HTTP traffic (unencrypted) vs HTTPS
        cursor.execute("""
            SELECT 
                COUNT(CASE WHEN protocol = 'HTTP' THEN 1 END) as http_count,
                COUNT(CASE WHEN protocol = 'HTTPS' THEN 1 END) as https_count
            FROM (
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name LIKE 'tcpdump_%'
                ORDER BY name DESC LIMIT 1
            ) AS latest_table,
            (SELECT * FROM tcpdump 
             WHERE src_ip = ? OR dest_ip = ?
             AND timestamp > datetime('now', '-1 hour')
             LIMIT 1000)
        """, (device_ip, device_ip))
        
        result = cursor.fetchone()
        conn.close()
        
        if result and result[0] > 0 and result[1] == 0:
            return True  # Only HTTP, no HTTPS
        return False
    
    def check_suspicious_connections(self, device_ip):
        """Check for suspicious outbound connections"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check for connections to suspicious IPs or high-risk ports
        cursor.execute("""
            SELECT COUNT(*) as suspicious_count
            FROM (
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name LIKE 'tcpdump_%'
                ORDER BY name DESC LIMIT 1
            ) AS latest_table,
            (SELECT * FROM tcpdump 
             WHERE src_ip = ?
             AND dest_ip NOT LIKE '192.168.%'
             AND dest_ip NOT LIKE '10.%'
             AND dest_ip NOT LIKE '172.%'
             AND dest_port IN (6667, 8080, 8443, 9001, 4444, 9999)
             AND timestamp > datetime('now', '-1 hour')
             LIMIT 1000)
        """, (device_ip,))
        
        result = cursor.fetchone()
        conn.close()
        
        return result[0] > 10 if result else False
    
    def check_device_specific_vulnerabilities(self, device, device_type):
        """Check for device-specific vulnerabilities"""
        vulnerabilities = []
        
        if 'camera' in device_type:
            vulnerabilities.append({
                'type': 'camera_privacy_risk',
                'severity': 2,  # HIGH
                'description': 'Camera device detected - potential privacy risk',
                'recommendation': 'Ensure camera is secured and not accessible from internet'
            })
        
        if 'tv' in device_type:
            vulnerabilities.append({
                'type': 'smart_tv_data_collection',
                'severity': 3,  # MEDIUM
                'description': 'Smart TV may be collecting viewing data',
                'recommendation': 'Review privacy settings and disable data collection'
            })
        
        return vulnerabilities
    
    def monitor_real_time_communications(self):
        """Monitor real-time device communications"""
        devices = self.get_iot_devices()
        
        for device in devices:
            device_ip = device['ip_address']
            
            # Get recent communication data
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Analyze recent traffic patterns
            cursor.execute("""
                SELECT 
                    dest_ip,
                    dest_port,
                    protocol,
                    COUNT(*) as packet_count,
                    SUM(data_size) as total_data
                FROM (
                    SELECT name FROM sqlite_master 
                    WHERE type='table' AND name LIKE 'tcpdump_%'
                    ORDER BY name DESC LIMIT 1
                ) AS latest_table,
                (SELECT * FROM tcpdump 
                 WHERE (src_ip = ? OR dest_ip = ?)
                 AND timestamp > datetime('now', '-5 minutes')
                 LIMIT 1000)
                GROUP BY dest_ip, dest_port, protocol
            """, (device_ip, device_ip))
            
            communications = cursor.fetchall()
            
            for comm in communications:
                dest_ip, dest_port, protocol, packet_count, total_data = comm
                
                # Determine risk level
                risk_level = self.assess_communication_risk(dest_ip, dest_port, protocol, packet_count, total_data)
                
                # Store communication record
                cursor.execute("""
                    INSERT INTO iot_communications 
                    (device_ip, device_mac, dest_ip, protocol, port, packet_count, data_size, risk_level, is_suspicious)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    device_ip,
                    device.get('mac_address'),
                    dest_ip,
                    protocol,
                    dest_port,
                    packet_count,
                    total_data,
                    risk_level,
                    1 if risk_level >= 3 else 0
                ))
            
            conn.commit()
            conn.close()
    
    def assess_communication_risk(self, dest_ip, dest_port, protocol, packet_count, total_data):
        """Assess risk level of a communication"""
        risk_score = 0
        
        # Check for external IPs
        if not (dest_ip.startswith('192.168.') or dest_ip.startswith('10.') or dest_ip.startswith('172.')):
            risk_score += 2
        
        # Check for suspicious ports
        suspicious_ports = [6667, 8080, 8443, 9001, 4444, 9999]
        if dest_port in suspicious_ports:
            risk_score += 3
        
        # Check for high data volume
        if total_data > 1000000:  # 1MB
            risk_score += 1
        
        # Check for high packet count
        if packet_count > 100:
            risk_score += 1
        
        # Normalize to 0-4 scale
        return min(4, risk_score)
    
    def analyze_behavioral_patterns(self):
        """Analyze behavioral patterns for anomaly detection"""
        devices = self.get_iot_devices()
        
        for device in devices:
            device_ip = device['ip_address']
            
            # Get recent activity data
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Calculate activity metrics
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_packets,
                    COUNT(DISTINCT dest_ip) as unique_destinations,
                    COUNT(DISTINCT dest_port) as unique_ports,
                    SUM(data_size) as total_data,
                    AVG(data_size) as avg_packet_size
                FROM (
                    SELECT name FROM sqlite_master 
                    WHERE type='table' AND name LIKE 'tcpdump_%'
                    ORDER BY name DESC LIMIT 1
                ) AS latest_table,
                (SELECT * FROM tcpdump 
                 WHERE src_ip = ?
                 AND timestamp > datetime('now', '-1 hour')
                 LIMIT 1000)
            """, (device_ip,))
            
            activity = cursor.fetchone()
            
            if activity and activity[0] > 0:
                # Calculate behavioral score
                behavioral_score = self.calculate_behavioral_score(activity, device_ip)
                
                # Determine activity type
                activity_type = "normal"
                if behavioral_score > 70:
                    activity_type = "suspicious"
                elif behavioral_score > 50:
                    activity_type = "anomalous"
                
                # Store behavioral data
                cursor.execute("""
                    INSERT INTO iot_behavioral_data 
                    (device_ip, device_mac, activity_type, activity_score, data_points)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    device_ip,
                    device.get('mac_address'),
                    activity_type,
                    behavioral_score,
                    json.dumps({
                        'total_packets': activity[0],
                        'unique_destinations': activity[1],
                        'unique_ports': activity[2],
                        'total_data': activity[3],
                        'avg_packet_size': activity[4]
                    })
                ))
            
            conn.commit()
            conn.close()
    
    def calculate_behavioral_score(self, activity, device_ip):
        """Calculate behavioral anomaly score"""
        total_packets, unique_destinations, unique_ports, total_data, avg_packet_size = activity
        
        score = 0
        
        # High packet count indicates potential scanning
        if total_packets > 500:
            score += 30
        
        # Many unique destinations indicates potential lateral movement
        if unique_destinations > 20:
            score += 25
        
        # Many unique ports indicates potential port scanning
        if unique_ports > 10:
            score += 20
        
        # Large data transfer indicates potential data exfiltration
        if total_data > 10000000:  # 10MB
            score += 15
        
        # Unusual packet sizes
        if avg_packet_size > 1000:
            score += 10
        
        return min(100, score)
    
    def track_domain_communications(self):
        """Track domain communication patterns"""
        devices = self.get_iot_devices()
        
        for device in devices:
            device_ip = device['ip_address']
            
            # Get DNS queries for this device (simulated)
            # In real implementation, you'd parse DNS traffic
            domains = self.extract_domains_from_traffic(device_ip)
            
            for domain in domains:
                # Check if domain is known
                risk_level = self.assess_domain_risk(domain)
                
                # Update or insert domain pattern
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT OR REPLACE INTO iot_domain_patterns 
                    (device_ip, domain, frequency, last_seen, risk_level)
                    VALUES (?, ?, COALESCE((SELECT frequency + 1 FROM iot_domain_patterns WHERE device_ip = ? AND domain = ?), 1), CURRENT_TIMESTAMP, ?)
                """, (device_ip, domain, device_ip, domain, risk_level))
                
                conn.commit()
                conn.close()
    
    def extract_domains_from_traffic(self, device_ip):
        """Extract domains from device traffic (simulated)"""
        # This is a simulation - in real implementation, you'd parse DNS queries
        # For now, we'll return some common domains based on device behavior
        
        common_domains = [
            "amazon.com", "google.com", "microsoft.com", "apple.com",
            "cloudflare.com", "akamai.net", "cdn.amazonaws.com"
        ]
        
        # Simulate domain extraction based on traffic patterns
        return common_domains[:3]  # Return 3 random domains
    
    def assess_domain_risk(self, domain):
        """Assess risk level of a domain"""
        # Check against known threat indicators
        for threat_type, indicators in self.threat_indicators.items():
            if domain in indicators.get('domains', []):
                return 4  # CRITICAL
        
        # Check for suspicious patterns
        suspicious_patterns = ['crypto', 'mining', 'pool', 'botnet', 'malware']
        if any(pattern in domain.lower() for pattern in suspicious_patterns):
            return 3  # HIGH
        
        # Check for data collection domains
        data_collection_domains = ['analytics', 'telemetry', 'tracking', 'metrics']
        if any(pattern in domain.lower() for pattern in data_collection_domains):
            return 2  # MEDIUM
        
        return 0  # SAFE
    
    def generate_security_scores(self):
        """Generate comprehensive security scores for all IoT devices"""
        devices = self.get_iot_devices()
        
        for device in devices:
            device_ip = device['ip_address']
            
            # Calculate vulnerability score
            vuln_score = self.calculate_vulnerability_score(device_ip)
            
            # Calculate communication score
            comm_score = self.calculate_communication_score(device_ip)
            
            # Calculate behavioral score
            behavior_score = self.calculate_behavioral_score_recent(device_ip)
            
            # Calculate overall score
            overall_score = (vuln_score + comm_score + behavior_score) // 3
            
            # Store security score
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Get existing score history
            cursor.execute("SELECT score_history FROM iot_security_scores WHERE device_ip = ?", (device_ip,))
            result = cursor.fetchone()
            
            score_history = []
            if result and result[0]:
                score_history = json.loads(result[0])
            
            # Add current score to history (keep last 24 scores)
            score_history.append({
                'timestamp': datetime.now().isoformat(),
                'overall_score': overall_score,
                'vulnerability_score': vuln_score,
                'communication_score': comm_score,
                'behavioral_score': behavior_score
            })
            
            if len(score_history) > 24:
                score_history = score_history[-24:]
            
            cursor.execute("""
                INSERT OR REPLACE INTO iot_security_scores 
                (device_ip, device_mac, overall_score, vulnerability_score, communication_score, behavioral_score, score_history)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                device_ip,
                device.get('mac_address'),
                overall_score,
                vuln_score,
                comm_score,
                behavior_score,
                json.dumps(score_history)
            ))
            
            conn.commit()
            conn.close()
    
    def calculate_vulnerability_score(self, device_ip):
        """Calculate vulnerability score (0-100, higher = more secure)"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM iot_vulnerabilities
            WHERE device_ip = ? AND resolved = 0
            GROUP BY severity
        """, (device_ip,))
        
        vulnerabilities = cursor.fetchall()
        conn.close()
        
        if not vulnerabilities:
            return 100  # No vulnerabilities = perfect score
        
        # Calculate weighted score
        total_penalty = 0
        for severity, count in vulnerabilities:
            penalty = severity * count * 10  # CRITICAL=40, HIGH=30, MEDIUM=20, LOW=10
            total_penalty += penalty
        
        score = max(0, 100 - total_penalty)
        return score
    
    def calculate_communication_score(self, device_ip):
        """Calculate communication security score"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                COUNT(*) as total_comm,
                SUM(CASE WHEN risk_level >= 3 THEN 1 ELSE 0 END) as high_risk_comm,
                SUM(CASE WHEN is_suspicious = 1 THEN 1 ELSE 0 END) as suspicious_comm
            FROM iot_communications
            WHERE device_ip = ? AND timestamp > datetime('now', '-1 hour')
        """, (device_ip,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result or result[0] == 0:
            return 100  # No communications = neutral score
        
        total_comm, high_risk_comm, suspicious_comm = result
        
        # Calculate score based on risk ratio
        risk_ratio = (high_risk_comm + suspicious_comm) / total_comm
        score = max(0, 100 - (risk_ratio * 100))
        
        return int(score)
    
    def calculate_behavioral_score_recent(self, device_ip):
        """Calculate recent behavioral score"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT AVG(activity_score) as avg_score
            FROM iot_behavioral_data
            WHERE device_ip = ? AND timestamp > datetime('now', '-1 hour')
        """, (device_ip,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result or not result[0]:
            return 100  # No recent activity = neutral score
        
        avg_score = result[0]
        # Convert to security score (higher behavioral score = lower security score)
        security_score = max(0, 100 - avg_score)
        
        return int(security_score)
    
    def create_security_alerts(self):
        """Create security alerts for detected threats"""
        devices = self.get_iot_devices()
        
        for device in devices:
            device_ip = device['ip_address']
            
            # Check for high-risk vulnerabilities
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT COUNT(*) as critical_vulns
                FROM iot_vulnerabilities
                WHERE device_ip = ? AND severity <= 2 AND resolved = 0
            """, (device_ip,))
            
            critical_vulns = cursor.fetchone()[0]
            
            if critical_vulns > 0:
                alert_id = f"IOT-CRITICAL-{device_ip}-{int(time.time())}"
                cursor.execute("""
                    INSERT OR IGNORE INTO iot_security_alerts
                    (alert_id, device_ip, alert_type, severity, title, description, threat_indicators, remediation_steps)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert_id,
                    device_ip,
                    'critical_vulnerabilities',
                    1,  # CRITICAL
                    f'Critical vulnerabilities detected on {device_ip}',
                    f'Device has {critical_vulns} critical/high severity vulnerabilities',
                    json.dumps(['critical_vulnerabilities', 'device_compromise']),
                    json.dumps(['Update firmware immediately', 'Change default credentials', 'Isolate device'])
                ))
            
            # Check for suspicious communications
            cursor.execute("""
                SELECT COUNT(*) as suspicious_comm
                FROM iot_communications
                WHERE device_ip = ? AND risk_level >= 3 AND timestamp > datetime('now', '-1 hour')
            """, (device_ip,))
            
            suspicious_comm = cursor.fetchone()[0]
            
            if suspicious_comm > 5:
                alert_id = f"IOT-SUSPICIOUS-{device_ip}-{int(time.time())}"
                cursor.execute("""
                    INSERT OR IGNORE INTO iot_security_alerts
                    (alert_id, device_ip, alert_type, severity, title, description, threat_indicators, remediation_steps)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert_id,
                    device_ip,
                    'suspicious_communications',
                    2,  # HIGH
                    f'Suspicious communications detected from {device_ip}',
                    f'Device made {suspicious_comm} high-risk communications in the last hour',
                    json.dumps(['suspicious_communications', 'potential_compromise']),
                    json.dumps(['Investigate communications', 'Block suspicious IPs', 'Monitor device behavior'])
                ))
            
            conn.commit()
            conn.close()
    
    def run_security_scan(self):
        """Run comprehensive security scan"""
        logging.info("Starting enhanced IoT security scan...")
        
        devices = self.get_iot_devices()
        logging.info(f"Found {len(devices)} IoT devices to scan")
        
        for device in devices:
            device_ip = device['ip_address']
            logging.info(f"Scanning device: {device_ip}")
            
            # Analyze vulnerabilities
            vulnerabilities = self.analyze_device_vulnerabilities(device)
            
            # Store vulnerabilities
            if vulnerabilities:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                
                for vuln in vulnerabilities:
                    cursor.execute("""
                        INSERT OR IGNORE INTO iot_vulnerabilities
                        (device_ip, device_mac, device_type, vulnerability_type, severity, description, recommendation)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        device_ip,
                        device.get('mac_address'),
                        device.get('device_category'),
                        vuln['type'],
                        vuln['severity'],
                        vuln['description'],
                        vuln['recommendation']
                    ))
                
                conn.commit()
                conn.close()
                logging.info(f"Found {len(vulnerabilities)} vulnerabilities on {device_ip}")
        
        # Monitor real-time communications
        self.monitor_real_time_communications()
        
        # Analyze behavioral patterns
        self.analyze_behavioral_patterns()
        
        # Track domain communications
        self.track_domain_communications()
        
        # Generate security scores
        self.generate_security_scores()
        
        # Create security alerts
        self.create_security_alerts()
        
        logging.info("Enhanced IoT security scan completed")
    
    def run_real_time_monitoring(self):
        """Run real-time monitoring loop"""
        logging.info("Starting real-time IoT monitoring...")
        
        while True:
            try:
                # Monitor communications
                self.monitor_real_time_communications()
                
                # Update behavioral analysis
                self.analyze_behavioral_patterns()
                
                # Update domain tracking
                self.track_domain_communications()
                
                # Update security scores
                self.generate_security_scores()
                
                # Check for new alerts
                self.create_security_alerts()
                
                time.sleep(REAL_TIME_INTERVAL)
                
            except Exception as e:
                logging.error(f"Error in real-time monitoring: {e}")
                time.sleep(REAL_TIME_INTERVAL)
    
    def main(self):
        """Main execution loop"""
        logging.info("=" * 60)
        logging.info("NetGuard Pro - Enhanced IoT Security Scanner")
        logging.info("=" * 60)
        
        # Run initial security scan
        self.run_security_scan()
        
        # Start real-time monitoring
        self.run_real_time_monitoring()

if __name__ == "__main__":
    scanner = EnhancedIoTSecurityScanner()
    scanner.main()
