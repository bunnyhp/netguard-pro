#!/usr/bin/env python3
"""
NetGuard Pro - Insert Sample AI Data for Testing
Creates realistic sample data to demonstrate AI dashboard
"""

import sqlite3
import json
from datetime import datetime

DB_PATH = "/home/jarvis/NetGuard/network.db"

def insert_sample_data():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    print("=" * 60)
    print("Inserting Sample AI Data for Dashboard Testing")
    print("=" * 60)
    
    # 1. Sample AI Prediction
    cursor.execute("""
        INSERT INTO ai_predictions (
            timestamp, analysis_window, threat_level, network_health_score,
            threats_detected, anomalies_detected, alerts_generated,
            threats_json, anomalies_json, patterns_json, processing_time_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().isoformat(),
        '5m',
        'MEDIUM',
        75,
        2,
        1,
        3,
        json.dumps([{
            "threat_id": "THR-TEST-001",
            "severity": "HIGH",
            "confidence": 0.87,
            "threat_type": "Port Scan",
            "source_ip": "192.168.1.unknown",
            "description": "Sequential port scanning detected on local network"
        }]),
        json.dumps([{
            "device_ip": "192.168.1.105",
            "device_name": "Smart TV",
            "anomaly_score": 0.72,
            "anomaly_type": "Unusual Traffic Volume"
        }]),
        json.dumps([{
            "pattern_type": "Suspicious DNS Queries",
            "confidence": 0.68,
            "device_ip": "192.168.1.120"
        }]),
        245
    ))
    print("✓ Inserted AI prediction")
    
    # 2. Sample Alerts
    alerts = [
        {
            'alert_id': 'ALT-TEST-001',
            'priority': 'CRITICAL',
            'title': 'Potential Data Exfiltration Detected',
            'message': 'Device 192.168.1.105 uploaded 2.5GB to unknown server in last hour',
            'threat_type': 'Data Exfiltration',
            'source_ip': '192.168.1.105',
            'confidence': 0.92,
            'indicators': ['Large upload volume', 'Unknown destination', 'Unusual time'],
            'recommended_action': 'Investigate device and consider quarantine',
            'auto_block': 0
        },
        {
            'alert_id': 'ALT-TEST-002',
            'priority': 'HIGH',
            'title': 'Port Scan Activity',
            'message': 'Sequential port scanning detected from external IP',
            'threat_type': 'Port Scan',
            'source_ip': '45.67.89.123',
            'confidence': 0.87,
            'indicators': ['50+ ports accessed', 'Sequential pattern', 'Short timeframe'],
            'recommended_action': 'Block source IP at firewall',
            'auto_block': 1
        },
        {
            'alert_id': 'ALT-TEST-003',
            'priority': 'MEDIUM',
            'title': 'Suspicious DNS Queries',
            'message': 'Device making queries to potential DGA domains',
            'threat_type': 'Malware Communication',
            'source_ip': '192.168.1.120',
            'confidence': 0.68,
            'indicators': ['Random domain patterns', 'High query frequency'],
            'recommended_action': 'Run antivirus scan on device',
            'auto_block': 0
        }
    ]
    
    for alert in alerts:
        cursor.execute("""
            INSERT INTO ai_alerts (
                alert_id, priority, title, message, threat_type,
                source_ip, confidence, indicators, recommended_action,
                auto_block, timestamp, resolved
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert['alert_id'],
            alert['priority'],
            alert['title'],
            alert['message'],
            alert['threat_type'],
            alert['source_ip'],
            alert['confidence'],
            json.dumps(alert['indicators']),
            alert['recommended_action'],
            alert['auto_block'],
            datetime.now().isoformat(),
            0
        ))
    print(f"✓ Inserted {len(alerts)} sample alerts")
    
    # 3. Sample URL Classifications
    urls = [
        {
            'url': 'http://suspicious-malware.xyz/download',
            'domain': 'suspicious-malware.xyz',
            'risk_score': 0.94,
            'category': 'Malware',
            'threat_intel_match': 1,
            'indicators': ['Blacklist match', 'Newly registered', 'Suspicious TLD'],
            'action': 'BLOCK',
            'accessed_by': ['192.168.1.105']
        },
        {
            'url': 'http://phishing-bank.com/login',
            'domain': 'phishing-bank.com',
            'risk_score': 0.89,
            'category': 'Phishing',
            'threat_intel_match': 1,
            'indicators': ['Typosquatting', 'SSL certificate mismatch'],
            'action': 'BLOCK',
            'accessed_by': ['192.168.1.110']
        },
        {
            'url': 'http://akjsdh23kjh.com',
            'domain': 'akjsdh23kjh.com',
            'risk_score': 0.78,
            'category': 'DGA',
            'threat_intel_match': 0,
            'indicators': ['Random string pattern', 'No DNS history'],
            'action': 'WARN',
            'accessed_by': ['192.168.1.120']
        }
    ]
    
    for url_data in urls:
        cursor.execute("""
            INSERT INTO url_classifications (
                url, domain, risk_score, category, threat_intel_match,
                indicators, action, accessed_by, first_seen, last_seen
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            url_data['url'],
            url_data['domain'],
            url_data['risk_score'],
            url_data['category'],
            url_data['threat_intel_match'],
            json.dumps(url_data['indicators']),
            url_data['action'],
            json.dumps(url_data['accessed_by']),
            datetime.now().isoformat(),
            datetime.now().isoformat()
        ))
    print(f"✓ Inserted {len(urls)} URL classifications")
    
    # 4. Sample Threat Patterns
    patterns = [
        {
            'pattern_type': 'Botnet Beacon',
            'device_ip': '192.168.1.120',
            'confidence': 0.82,
            'description': 'Regular periodic connections to external server detected',
            'characteristics': json.dumps({
                'interval': 60,
                'destination': '45.67.89.123',
                'port': 8443,
                'consistency': 0.95
            }),
            'severity': 'HIGH'
        },
        {
            'pattern_type': 'Data Exfiltration',
            'device_ip': '192.168.1.105',
            'confidence': 0.76,
            'description': 'Unusual large data upload pattern detected',
            'characteristics': json.dumps({
                'upload_size': '2.5GB',
                'duration': '45 minutes',
                'destination': 'unknown'
            }),
            'severity': 'HIGH'
        }
    ]
    
    for pattern in patterns:
        cursor.execute("""
            INSERT INTO threat_patterns (
                pattern_type, device_ip, confidence, description,
                characteristics, first_detected, last_detected, severity, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            pattern['pattern_type'],
            pattern['device_ip'],
            pattern['confidence'],
            pattern['description'],
            pattern['characteristics'],
            datetime.now().isoformat(),
            datetime.now().isoformat(),
            pattern['severity'],
            'active'
        ))
    print(f"✓ Inserted {len(patterns)} threat patterns")
    
    # 5. Sample Device Profiles
    devices = [
        {
            'device_ip': '192.168.1.100',
            'device_name': 'iPhone',
            'device_type': 'smartphone',
            'profile_confidence': 0.9
        },
        {
            'device_ip': '192.168.1.105',
            'device_name': 'Smart TV',
            'device_type': 'iot',
            'profile_confidence': 0.85
        },
        {
            'device_ip': '192.168.1.110',
            'device_name': 'Laptop',
            'device_type': 'computer',
            'profile_confidence': 0.95
        }
    ]
    
    for device in devices:
        cursor.execute("""
            INSERT INTO device_profiles (
                device_ip, device_name, device_type, profile_confidence,
                first_seen, last_updated, days_observed
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            device['device_ip'],
            device['device_name'],
            device['device_type'],
            device['profile_confidence'],
            datetime.now().isoformat(),
            datetime.now().isoformat(),
            7
        ))
    print(f"✓ Inserted {len(devices)} device profiles")
    
    # 6. Sample Analysis History
    for i in range(24):
        cursor.execute("""
            INSERT INTO ai_analysis_history (
                timestamp, packets_analyzed, devices_analyzed,
                threats_found, alerts_generated, analysis_duration_ms, success
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().isoformat(),
            100 + (i * 10),
            3 + (i % 3),
            i % 3,
            i % 2,
            200 + (i * 5),
            1
        ))
    print("✓ Inserted 24 analysis history records")
    
    conn.commit()
    conn.close()
    
    print("=" * 60)
    print("✅ Sample Data Inserted Successfully!")
    print("=" * 60)
    print("\n🌐 View the AI Dashboard at:")
    print("http://192.168.1.161:8080/ai-dashboard")
    print("\nNote: This is sample data for demonstration purposes.")
    print("Real data will come from the AI analysis service.")


if __name__ == "__main__":
    insert_sample_data()

