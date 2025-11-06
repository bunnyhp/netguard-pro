#!/usr/bin/env python3
"""
NetGuard Pro - Device Security Scorer
Calculates security scores (0-100) for all tracked devices
"""

import sqlite3
import logging
import sys
from datetime import datetime, timedelta

DB_PATH = "/home/jarvis/NetGuard/network.db"
LOG_FILE = "/home/jarvis/NetGuard/logs/system/device-scorer.log"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

class DeviceScorer:
    """Calculate security scores for devices based on multiple factors"""
    
    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
    
    def calculate_device_score(self, device):
        """Calculate security score for a single device (0-100)"""
        score = 100  # Start with perfect score
        reasons = []
        
        # Factor 1: Device Identification (-20 if unknown)
        if not device['hostname'] or device['hostname'] == '':
            score -= 10
            reasons.append("No hostname resolution (-10)")
        
        if not device['mac_address']:
            score -= 15
            reasons.append("No MAC address identified (-15)")
        
        if device['device_type'] == 'Unknown':
            score -= 10
            reasons.append("Unknown device type (-10)")
        
        # Factor 2: Vulnerabilities (check iot_vulnerabilities table)
        self.cursor.execute("""
            SELECT COUNT(*) as vuln_count,
                   MAX(CASE severity
                       WHEN 'CRITICAL' THEN 4
                       WHEN 'HIGH' THEN 3
                       WHEN 'MEDIUM' THEN 2
                       WHEN 'LOW' THEN 1
                       ELSE 0
                   END) as max_severity
            FROM iot_vulnerabilities
            WHERE device_ip = ? AND resolved = 0
        """, (device['ip_address'],))
        
        vuln_result = self.cursor.fetchone()
        if vuln_result and vuln_result['vuln_count'] > 0:
            vuln_count = vuln_result['vuln_count']
            max_severity = vuln_result['max_severity']
            
            if max_severity == 4:  # CRITICAL
                score -= 40
                reasons.append(f"Critical vulnerabilities detected ({vuln_count}) (-40)")
            elif max_severity == 3:  # HIGH
                score -= 25
                reasons.append(f"High severity vulnerabilities ({vuln_count}) (-25)")
            elif max_severity == 2:  # MEDIUM
                score -= 15
                reasons.append(f"Medium severity vulnerabilities ({vuln_count}) (-15)")
            elif max_severity == 1:  # LOW
                score -= 5
                reasons.append(f"Low severity vulnerabilities ({vuln_count}) (-5)")
        
        # Factor 3: Network Activity (check for suspicious connections)
        # Check recent traffic for unencrypted HTTP
        try:
            self.cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND (name LIKE 'tshark_%' OR name LIKE 'tcpdump_%')
                AND name NOT LIKE '%_template'
                ORDER BY name DESC LIMIT 1
            """)
            table_result = self.cursor.fetchone()
            
            if table_result:
                table_name = table_result['name']
                
                # Check HTTP vs HTTPS ratio
                self.cursor.execute(f"""
                    SELECT 
                        COUNT(CASE WHEN dest_port = 80 THEN 1 END) as http_count,
                        COUNT(CASE WHEN dest_port = 443 THEN 1 END) as https_count
                    FROM {table_name}
                    WHERE src_ip = ?
                    AND dest_port IN (80, 443)
                """, (device['ip_address'],))
                
                traffic_result = self.cursor.fetchone()
                if traffic_result:
                    http_count = traffic_result['http_count']
                    https_count = traffic_result['https_count']
                    total_web = http_count + https_count
                    
                    if total_web > 10 and http_count > 0:
                        http_ratio = (http_count / total_web * 100)
                        if http_ratio > 70:
                            score -= 15
                            reasons.append(f"High unencrypted traffic ({http_ratio:.0f}% HTTP) (-15)")
                        elif http_ratio > 40:
                            score -= 8
                            reasons.append(f"Moderate unencrypted traffic ({http_ratio:.0f}% HTTP) (-8)")
        except Exception as e:
            logging.debug(f"Error checking traffic for {device['ip_address']}: {e}")
        
        # Factor 4: Device Activity (last seen)
        if device['last_seen']:
            last_seen = datetime.fromisoformat(device['last_seen'])
            hours_inactive = (datetime.now() - last_seen).total_seconds() / 3600
            
            if hours_inactive > 24:
                score -= 5
                reasons.append("Device inactive >24 hours (-5)")
        
        # Factor 5: IoT Device Bonus/Penalty
        if device['device_type'] == 'IoT':
            # IoT devices are inherently riskier
            score -= 5
            reasons.append("IoT device (inherent risk) (-5)")
            
            # But if it's properly categorized, give back some points
            if device['device_category'] and device['device_category'] != 'Unknown':
                score += 3
                reasons.append("Properly categorized (+3)")
        
        # Factor 6: Network Device Security
        if device['device_type'] == 'Network':
            # Routers/switches are critical infrastructure
            score += 10
            reasons.append("Network infrastructure device (+10)")
        
        # Ensure score stays within bounds
        score = max(0, min(100, score))
        
        return score, reasons
    
    def update_all_scores(self):
        """Update security scores for all devices"""
        logging.info("Calculating security scores for all devices...")
        
        self.cursor.execute("SELECT * FROM devices")
        devices = self.cursor.fetchall()
        
        updated_count = 0
        score_distribution = {'A': 0, 'B': 0, 'C': 0, 'D': 0, 'F': 0}
        
        for device in devices:
            device_dict = dict(device)
            score, reasons = self.calculate_device_score(device_dict)
            
            # Update the security score
            self.cursor.execute("""
                UPDATE devices 
                SET security_score = ?
                WHERE ip_address = ?
            """, (score, device_dict['ip_address']))
            
            updated_count += 1
            
            # Track score distribution
            if score >= 90:
                score_distribution['A'] += 1
                grade = 'A'
            elif score >= 80:
                score_distribution['B'] += 1
                grade = 'B'
            elif score >= 70:
                score_distribution['C'] += 1
                grade = 'C'
            elif score >= 60:
                score_distribution['D'] += 1
                grade = 'D'
            else:
                score_distribution['F'] += 1
                grade = 'F'
            
            logging.info(f"  {device_dict['ip_address']:15s} | Score: {score:3d}/100 (Grade {grade}) | {device_dict['device_category'] or 'Unknown'}")
            if reasons and score < 80:
                for reason in reasons[:3]:  # Show top 3 reasons
                    logging.info(f"    - {reason}")
        
        self.conn.commit()
        
        logging.info(f"\n✓ Updated {updated_count} device security scores")
        logging.info(f"Score Distribution: A={score_distribution['A']}, B={score_distribution['B']}, C={score_distribution['C']}, D={score_distribution['D']}, F={score_distribution['F']}")
        
        return updated_count, score_distribution
    
    def get_at_risk_devices(self, threshold=60):
        """Get devices with security score below threshold"""
        self.cursor.execute("""
            SELECT ip_address, hostname, device_type, device_category, 
                   security_score, vendor
            FROM devices
            WHERE security_score < ?
            ORDER BY security_score ASC
        """, (threshold,))
        
        return [dict(row) for row in self.cursor.fetchall()]
    
    def close(self):
        """Close database connection"""
        self.conn.close()

def main():
    """Main scoring function"""
    logging.info("=" * 60)
    logging.info("NetGuard Pro - Device Security Scorer")
    logging.info("=" * 60)
    
    try:
        scorer = DeviceScorer()
        updated, distribution = scorer.update_all_scores()
        
        # Show at-risk devices
        at_risk = scorer.get_at_risk_devices(threshold=70)
        if at_risk:
            logging.info(f"\n⚠️  {len(at_risk)} device(s) need attention (score < 70):")
            for device in at_risk:
                logging.info(f"  - {device['ip_address']:15s} ({device['hostname'] or 'Unknown'}): {device['security_score']}/100")
        else:
            logging.info("\n✓ All devices have acceptable security scores!")
        
        scorer.close()
        return 0
        
    except Exception as e:
        logging.error(f"Error during scoring: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())

