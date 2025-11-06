#!/usr/bin/env python3
"""
NetGuard Pro - AI Service Connector
Sends data to AI analysis service and receives threat predictions
"""

import requests
import json
import sqlite3
import logging
from datetime import datetime
from ai_data_exporter import export_to_ai_format

DB_PATH = "/home/jarvis/NetGuard/network.db"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


def get_ai_config():
    """Load AI configuration from database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT key, value FROM ai_config")
    config = {row[0]: row[1] for row in cursor.fetchall()}
    conn.close()
    
    return config


def send_to_ai_service(data, config):
    """
    Send network data to AI service for analysis
    
    Args:
        data: Network data in JSON format
        config: AI configuration dict
        
    Returns:
        AI analysis response or None if error
    """
    
    ai_url = config.get('ai_service_url', 'http://localhost:5000')
    endpoint = f"{ai_url}/api/v1/analyze"
    
    logging.info(f"Sending data to AI service: {endpoint}")
    
    try:
        response = requests.post(
            endpoint,
            json=data,
            timeout=10,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            result = response.json()
            logging.info(f"✓ AI analysis received: {result.get('statistics', {}).get('threats_found', 0)} threats found")
            return result
        else:
            logging.error(f"AI service error: {response.status_code} - {response.text}")
            return None
            
    except requests.exceptions.ConnectionError:
        logging.warning("Cannot connect to AI service - is it running?")
        return None
    except requests.exceptions.Timeout:
        logging.error("AI service timeout")
        return None
    except Exception as e:
        logging.error(f"Error calling AI service: {e}")
        return None


def store_ai_predictions(ai_response):
    """Store AI analysis results in database"""
    if not ai_response:
        return False
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # Store main prediction
        cursor.execute("""
            INSERT INTO ai_predictions (
                timestamp, analysis_window, threat_level, network_health_score,
                threats_detected, anomalies_detected, alerts_generated,
                threats_json, anomalies_json, patterns_json, dns_analysis_json,
                processing_time_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ai_response.get('analysis_timestamp'),
            '5m',
            ai_response.get('overall_threat_level'),
            ai_response.get('network_health_score'),
            len(ai_response.get('threats_detected', [])),
            len(ai_response.get('device_anomalies', [])),
            len(ai_response.get('alerts', [])),
            json.dumps(ai_response.get('threats_detected', [])),
            json.dumps(ai_response.get('device_anomalies', [])),
            json.dumps(ai_response.get('behavior_patterns', [])),
            json.dumps(ai_response.get('dns_analysis', [])),
            ai_response.get('statistics', {}).get('processing_time_ms', 0)
        ))
        
        prediction_id = cursor.lastrowid
        
        # Store alerts
        for alert in ai_response.get('alerts', []):
            cursor.execute("""
                INSERT INTO ai_alerts (
                    alert_id, priority, title, message, threat_type,
                    source_ip, confidence, indicators, recommended_action,
                    auto_block, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.get('alert_id'),
                alert.get('priority'),
                alert.get('title'),
                alert.get('message'),
                alert.get('threat_type', 'Unknown'),
                alert.get('source_ip'),
                alert.get('confidence', 0.0),
                json.dumps(alert.get('indicators', [])),
                alert.get('recommended_action'),
                1 if alert.get('auto_block') else 0,
                datetime.now().isoformat()
            ))
        
        # Store URL classifications
        for url_data in ai_response.get('url_classifications', []):
            cursor.execute("""
                INSERT OR REPLACE INTO url_classifications (
                    url, domain, risk_score, category, threat_intel_match,
                    indicators, action, accessed_by, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                url_data.get('url'),
                url_data.get('domain'),
                url_data.get('risk_score'),
                url_data.get('category'),
                1 if url_data.get('threat_intel_match') else 0,
                json.dumps(url_data.get('indicators', [])),
                url_data.get('action'),
                json.dumps(url_data.get('accessed_by', [])),
                datetime.now().isoformat(),
                datetime.now().isoformat()
            ))
        
        # Store threat patterns
        for pattern in ai_response.get('behavior_patterns', []):
            cursor.execute("""
                INSERT INTO threat_patterns (
                    pattern_type, device_ip, confidence, description,
                    characteristics, first_detected, last_detected, severity
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                pattern.get('pattern_type'),
                pattern.get('device_ip'),
                pattern.get('confidence'),
                pattern.get('description'),
                json.dumps(pattern.get('characteristics', {})),
                datetime.now().isoformat(),
                datetime.now().isoformat(),
                'HIGH' if pattern.get('confidence', 0) > 0.8 else 'MEDIUM'
            ))
        
        # Store device anomalies as updates to device profiles
        for anomaly in ai_response.get('device_anomalies', []):
            device_ip = anomaly.get('device_ip')
            if device_ip:
                cursor.execute("""
                    INSERT OR REPLACE INTO device_profiles (
                        device_ip, device_name, last_updated
                    ) VALUES (?, ?, ?)
                """, (
                    device_ip,
                    anomaly.get('device_name', 'Unknown'),
                    datetime.now().isoformat()
                ))
        
        # Store analysis history
        cursor.execute("""
            INSERT INTO ai_analysis_history (
                timestamp, packets_analyzed, devices_analyzed,
                threats_found, alerts_generated, analysis_duration_ms, success
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().isoformat(),
            ai_response.get('statistics', {}).get('packets_analyzed', 0),
            ai_response.get('statistics', {}).get('devices_monitored', 0),
            ai_response.get('statistics', {}).get('threats_found', 0),
            len(ai_response.get('alerts', [])),
            ai_response.get('statistics', {}).get('processing_time_ms', 0),
            1
        ))
        
        conn.commit()
        logging.info(f"✓ Stored AI results: {len(ai_response.get('alerts', []))} alerts, "
                    f"{len(ai_response.get('threats_detected', []))} threats")
        
        return True
        
    except Exception as e:
        logging.error(f"Error storing AI predictions: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()


def analyze_network():
    """Main function: Export data, send to AI, store results"""
    
    logging.info("=" * 60)
    logging.info("NetGuard Pro - AI Analysis Cycle")
    logging.info("=" * 60)
    
    # Get configuration
    config = get_ai_config()
    
    # Check if AI is enabled
    if config.get('ai_enabled', '0') == '0':
        logging.info("AI analysis is disabled in configuration")
        return False
    
    # Export network data
    logging.info("Step 1: Exporting network data...")
    network_data = export_to_ai_format(time_window_minutes=5)
    
    if not network_data:
        logging.warning("No data to analyze")
        return False
    
    logging.info(f"✓ Exported {network_data['network_metrics']['total_packets']} packets")
    
    # Send to AI service
    logging.info("Step 2: Sending to AI service...")
    ai_response = send_to_ai_service(network_data, config)
    
    if not ai_response:
        logging.warning("No response from AI service")
        # Store failed attempt in history
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO ai_analysis_history (
                timestamp, packets_analyzed, success, error_message
            ) VALUES (?, ?, ?, ?)
        """, (
            datetime.now().isoformat(),
            network_data['network_metrics']['total_packets'],
            0,
            'AI service unavailable'
        ))
        conn.commit()
        conn.close()
        return False
    
    # Store results
    logging.info("Step 3: Storing AI predictions...")
    success = store_ai_predictions(ai_response)
    
    if success:
        logging.info("=" * 60)
        logging.info("✅ AI Analysis Complete!")
        logging.info(f"   Threat Level: {ai_response.get('overall_threat_level')}")
        logging.info(f"   Health Score: {ai_response.get('network_health_score')}/100")
        logging.info(f"   Threats: {len(ai_response.get('threats_detected', []))}")
        logging.info(f"   Alerts: {len(ai_response.get('alerts', []))}")
        logging.info("=" * 60)
    
    return success


if __name__ == "__main__":
    # Run analysis
    success = analyze_network()
    
    if not success:
        logging.info("\nℹ️  Note: AI service must be running for analysis")
        logging.info("   Current status: AI service not available")
        logging.info("   Configure AI service URL in ai_config table")

