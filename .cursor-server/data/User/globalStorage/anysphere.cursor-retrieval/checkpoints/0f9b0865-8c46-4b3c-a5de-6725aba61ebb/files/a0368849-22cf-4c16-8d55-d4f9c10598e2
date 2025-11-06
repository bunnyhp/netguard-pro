#!/usr/bin/env python3
"""
NetGuard Pro - 5-Minute AI Data Aggregator
Collects data from all 10 network monitoring tools every 5 minutes
Sends comprehensive data to AI for analysis and threat detection
"""

import os
import sys
import json
import sqlite3
import logging
import time
from datetime import datetime, timedelta
import requests

# Configuration
DB_PATH = "/home/jarvis/NetGuard/network.db"
CONFIG_PATH = "/home/jarvis/NetGuard/config/ai_config.json"
LOG_FILE = "/home/jarvis/NetGuard/logs/system/ai-5min-aggregator.log"
AI_RESULTS_DB = "/home/jarvis/NetGuard/network.db"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

def load_config():
    """Load AI configuration"""
    try:
        with open(CONFIG_PATH, 'r') as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Error loading config: {e}")
        return None

def get_latest_table(conn, prefix):
    """Get the most recent table for a given prefix"""
    cursor = conn.cursor()
    cursor.execute(f"""
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name LIKE '{prefix}_%' 
        ORDER BY name DESC LIMIT 1
    """)
    result = cursor.fetchone()
    return result[0] if result else None

def aggregate_data_last_5min():
    """Aggregate data from all tools from the last 5 minutes"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        
        data = {
            'timestamp': datetime.now().isoformat(),
            'collection_period': '5 minutes',
            'tools': {}
        }
        
        # 1. P0F - OS Fingerprinting
        table = get_latest_table(conn, 'p0f')
        if table:
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM {table} ORDER BY created_at DESC LIMIT 50")
            rows = cursor.fetchall()
            data['tools']['p0f'] = {
                'total_fingerprints': len(rows),
                'os_detected': [dict(row) for row in rows[:10]],
                'unique_ips': len(set(dict(row)['src_ip'] for row in rows if dict(row).get('src_ip')))
            }
        
        # 2. TSHARK - Packet Capture
        table = get_latest_table(conn, 'tshark')
        if table:
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM {table} ORDER BY timestamp DESC LIMIT 100")
            rows = cursor.fetchall()
            protocols = {}
            for row in rows:
                proto = dict(row).get('protocol', 'Unknown')
                protocols[proto] = protocols.get(proto, 0) + 1
            data['tools']['tshark'] = {
                'total_packets': len(rows),
                'protocol_distribution': protocols,
                'sample_packets': [dict(row) for row in rows[:5]]
            }
        
        # 3. NGREP - Content Inspection
        table = get_latest_table(conn, 'ngrep')
        if table:
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM {table} ORDER BY created_at DESC LIMIT 100")
            rows = cursor.fetchall()
            data['tools']['ngrep'] = {
                'total_matches': len(rows),
                'tcp_connections': [dict(row) for row in rows[:10]]
            }
        
        # 4. HTTPRY - HTTP Logging
        table = get_latest_table(conn, 'httpry')
        if table:
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM {table} ORDER BY created_at DESC LIMIT 100")
            rows = cursor.fetchall()
            methods = {}
            hosts = {}
            for row in rows:
                method = dict(row).get('method', 'Unknown')
                host = dict(row).get('host', 'Unknown')
                methods[method] = methods.get(method, 0) + 1
                hosts[host] = hosts.get(host, 0) + 1
            data['tools']['httpry'] = {
                'total_requests': len(rows),
                'http_methods': methods,
                'top_hosts': dict(sorted(hosts.items(), key=lambda x: x[1], reverse=True)[:10]),
                'sample_requests': [dict(row) for row in rows[:5]]
            }
        
        # 5. TCPDUMP - Professional Packet Capture
        table = get_latest_table(conn, 'tcpdump')
        if table:
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM {table} ORDER BY timestamp DESC LIMIT 200")
            rows = cursor.fetchall()
            data['tools']['tcpdump'] = {
                'total_packets': len(rows),
                'sample_packets': [dict(row) for row in rows[:10]]
            }
        
        # 6. ARGUS - Flow Analysis
        table = get_latest_table(conn, 'argus')
        if table:
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM {table} ORDER BY created_at DESC LIMIT 100")
            rows = cursor.fetchall()
            data['tools']['argus'] = {
                'total_flows': len(rows),
                'flows': [dict(row) for row in rows[:10]]
            }
        
        # 7. NETSNIFF - Network Sniffing
        table = get_latest_table(conn, 'netsniff')
        if table:
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM {table} ORDER BY created_at DESC LIMIT 100")
            rows = cursor.fetchall()
            data['tools']['netsniff'] = {
                'total_packets': len(rows),
                'packets': [dict(row) for row in rows[:10]]
            }
        
        # 8. IFTOP - Bandwidth Monitoring
        table = get_latest_table(conn, 'iftop')
        if table:
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM {table} ORDER BY created_at DESC LIMIT 50")
            rows = cursor.fetchall()
            data['tools']['iftop'] = {
                'total_connections': len(rows),
                'bandwidth_data': [dict(row) for row in rows[:10]]
            }
        
        # 9. NETHOGS - Process Bandwidth
        table = get_latest_table(conn, 'nethogs')
        if table:
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM {table} ORDER BY created_at DESC LIMIT 100")
            rows = cursor.fetchall()
            data['tools']['nethogs'] = {
                'total_processes': len(rows),
                'top_bandwidth_users': [dict(row) for row in rows[:10]]
            }
        
        # 10. SURICATA - IDS/IPS
        # Get alerts
        table = get_latest_table(conn, 'suricata_alerts')
        if table:
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM {table} ORDER BY timestamp DESC LIMIT 50")
            alerts = cursor.fetchall()
            data['tools']['suricata'] = {
                'total_alerts': len(alerts),
                'alerts': [dict(row) for row in alerts[:10]]
            }
        else:
            data['tools']['suricata'] = {'total_alerts': 0, 'alerts': []}
        
        # Get flows
        table = get_latest_table(conn, 'suricata_flow')
        if table:
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM {table} ORDER BY timestamp DESC LIMIT 50")
            flows = cursor.fetchall()
            data['tools']['suricata']['total_flows'] = len(flows)
            data['tools']['suricata']['flows'] = [dict(row) for row in flows[:5]]
        
        conn.close()
        return data
        
    except Exception as e:
        logging.error(f"Error aggregating data: {e}")
        return None

def build_ai_prompt(data):
    """Build comprehensive AI analysis prompt"""
    
    prompt = f"""You are a professional network security analyst. Analyze the following 5-minute network monitoring data from 10 different security tools and provide a comprehensive threat assessment.

## DATA COLLECTED ({data['timestamp']})

### 1. OS FINGERPRINTING (p0f)
- Total Fingerprints: {data['tools'].get('p0f', {}).get('total_fingerprints', 0)}
- Unique IP Addresses: {data['tools'].get('p0f', {}).get('unique_ips', 0)}

### 2. PACKET CAPTURE (tshark)
- Total Packets: {data['tools'].get('tshark', {}).get('total_packets', 0)}
- Protocol Distribution: {json.dumps(data['tools'].get('tshark', {}).get('protocol_distribution', {}), indent=2)}

### 3. CONTENT INSPECTION (ngrep)
- Total TCP Matches: {data['tools'].get('ngrep', {}).get('total_matches', 0)}

### 4. HTTP TRAFFIC (httpry)
- Total HTTP Requests: {data['tools'].get('httpry', {}).get('total_requests', 0)}
- HTTP Methods: {json.dumps(data['tools'].get('httpry', {}).get('http_methods', {}), indent=2)}
- Top Hosts: {json.dumps(data['tools'].get('httpry', {}).get('top_hosts', {}), indent=2)}

### 5. DEEP PACKET ANALYSIS (tcpdump)
- Total Packets: {data['tools'].get('tcpdump', {}).get('total_packets', 0)}

### 6. FLOW ANALYSIS (argus)
- Total Network Flows: {data['tools'].get('argus', {}).get('total_flows', 0)}

### 7. NETWORK SNIFFING (netsniff-ng)
- Total Packets: {data['tools'].get('netsniff', {}).get('total_packets', 0)}

### 8. BANDWIDTH MONITORING (iftop)
- Active Connections: {data['tools'].get('iftop', {}).get('total_connections', 0)}

### 9. PROCESS MONITORING (nethogs)
- Active Processes: {data['tools'].get('nethogs', {}).get('total_processes', 0)}

### 10. INTRUSION DETECTION (Suricata)
- Total Alerts: {data['tools'].get('suricata', {}).get('total_alerts', 0)}
- Network Flows: {data['tools'].get('suricata', {}).get('total_flows', 0)}

## ANALYSIS REQUEST

Please provide a comprehensive JSON response with the following structure:

{{
  "threat_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "network_health_score": 0-100,
  "summary": "Brief 2-3 sentence summary of network status",
  "threats_detected": [
    {{
      "severity": "LOW|MEDIUM|HIGH|CRITICAL",
      "category": "Malware|DDoS|Scan|Exploit|Anomaly|Suspicious",
      "description": "Detailed threat description",
      "affected_ips": ["ip1", "ip2"],
      "recommended_action": "What should be done",
      "tool_source": "Which tool detected this"
    }}
  ],
  "network_insights": {{
    "total_traffic_volume": "Estimated volume",
    "most_active_protocols": ["proto1", "proto2"],
    "suspicious_connections": 0,
    "unusual_patterns": ["pattern1", "pattern2"],
    "bandwidth_anomalies": ["anomaly1", "anomaly2"]
  }},
  "device_analysis": {{
    "total_devices": 0,
    "operating_systems": {{"OS1": count1}},
    "suspicious_devices": ["ip1: reason"]
  }},
  "http_analysis": {{
    "total_requests": 0,
    "suspicious_urls": ["url1: reason"],
    "unusual_user_agents": ["agent1: reason"]
  }},
  "recommendations": [
    "Immediate action item 1",
    "Immediate action item 2"
  ]
}}

Provide ONLY the JSON response, no additional text."""

    return prompt

def call_gemini_api(prompt, api_key):
    """Call Google Gemini API"""
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-exp:generateContent?key={api_key}"
        headers = {'Content-Type': 'application/json'}
        
        payload = {
            "contents": [{
                "parts": [{"text": prompt}]
            }],
            "generationConfig": {
                "temperature": 0.3,
                "topK": 40,
                "topP": 0.95,
                "maxOutputTokens": 4096,
            }
        }
        
        response = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=60
        )
        
        if response.status_code == 200:
            result = response.json()
            text = result['candidates'][0]['content']['parts'][0]['text']
            # Extract JSON from markdown code blocks if present
            if '```json' in text:
                text = text.split('```json')[1].split('```')[0].strip()
            elif '```' in text:
                text = text.split('```')[1].split('```')[0].strip()
            return json.loads(text)
        else:
            logging.error(f"Gemini API error: {response.status_code} - {response.text}")
            return None
            
    except Exception as e:
        logging.error(f"Error calling Gemini API: {e}")
        return None

def store_ai_results(analysis):
    """Store AI analysis results in database"""
    try:
        conn = sqlite3.connect(AI_RESULTS_DB)
        cursor = conn.cursor()
        
        # Create table if not exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ai_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                threat_level TEXT,
                network_health_score INTEGER,
                summary TEXT,
                threats_detected TEXT,
                network_insights TEXT,
                device_analysis TEXT,
                http_analysis TEXT,
                recommendations TEXT,
                raw_response TEXT
            )
        """)
        
        # Insert analysis
        cursor.execute("""
            INSERT INTO ai_analysis (
                threat_level, network_health_score, summary,
                threats_detected, network_insights, device_analysis,
                http_analysis, recommendations, raw_response
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            analysis.get('threat_level'),
            analysis.get('network_health_score'),
            analysis.get('summary'),
            json.dumps(analysis.get('threats_detected', [])),
            json.dumps(analysis.get('network_insights', {})),
            json.dumps(analysis.get('device_analysis', {})),
            json.dumps(analysis.get('http_analysis', {})),
            json.dumps(analysis.get('recommendations', [])),
            json.dumps(analysis)
        ))
        
        conn.commit()
        analysis_id = cursor.lastrowid
        conn.close()
        
        logging.info(f"✓ Stored AI analysis with ID: {analysis_id}")
        return analysis_id
        
    except Exception as e:
        logging.error(f"Error storing AI results: {e}")
        return None

def main():
    """Main execution loop"""
    logging.info("=" * 60)
    logging.info("NetGuard Pro - 5-Minute AI Data Aggregator")
    logging.info("=" * 60)
    
    # Load configuration
    config = load_config()
    if not config or not config.get('ai_enabled'):
        logging.error("AI is not enabled in configuration")
        return 1
    
    api_key = config.get('api_keys', {}).get('gemini_api_key')
    if not api_key:
        logging.error("Gemini API key not found in configuration")
        return 1
    
    interval = config.get('analysis_interval_minutes', 5) * 60
    
    logging.info(f"AI Analysis Interval: {interval} seconds ({interval//60} minutes)")
    logging.info(f"Starting continuous AI analysis...")
    
    cycle = 0
    
    try:
        while True:
            cycle += 1
            logging.info(f"\n{'='*60}")
            logging.info(f"AI Analysis Cycle {cycle}")
            logging.info(f"{'='*60}")
            
            # 1. Aggregate data
            logging.info("Step 1: Aggregating data from all 10 tools...")
            data = aggregate_data_last_5min()
            
            if not data:
                logging.warning("No data collected, skipping this cycle")
                time.sleep(interval)
                continue
            
            # Log data summary
            tool_count = sum(1 for tool in data['tools'].values() if tool)
            logging.info(f"✓ Collected data from {tool_count} tools")
            
            # 2. Build AI prompt
            logging.info("Step 2: Building AI analysis prompt...")
            prompt = build_ai_prompt(data)
            
            # 3. Call AI API
            logging.info("Step 3: Sending data to Gemini AI for analysis...")
            analysis = call_gemini_api(prompt, api_key)
            
            if analysis:
                logging.info(f"✓ AI Analysis completed")
                logging.info(f"  Threat Level: {analysis.get('threat_level')}")
                logging.info(f"  Network Health: {analysis.get('network_health_score')}/100")
                logging.info(f"  Threats Detected: {len(analysis.get('threats_detected', []))}")
                
                # 4. Store results
                logging.info("Step 4: Storing AI analysis results...")
                analysis_id = store_ai_results(analysis)
                
                if analysis_id:
                    logging.info(f"✓ Analysis cycle {cycle} completed successfully")
                else:
                    logging.error("Failed to store AI results")
            else:
                logging.error("AI analysis failed")
            
            # Wait for next cycle
            logging.info(f"\nWaiting {interval} seconds until next analysis...")
            time.sleep(interval)
            
    except KeyboardInterrupt:
        logging.info("\n✓ Shutdown signal received")
        return 0
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())

