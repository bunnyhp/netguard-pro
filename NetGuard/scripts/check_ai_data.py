#!/usr/bin/env python3
"""Quick script to check AI analysis data"""
import sqlite3
import json

DB_PATH = "/home/jarvis/NetGuard/network.db"

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# Get latest AI analysis
cursor.execute("""
    SELECT id, timestamp, threat_level, network_health_score, 
           summary, threats_detected, network_insights, device_analysis
    FROM ai_analysis 
    ORDER BY timestamp DESC 
    LIMIT 1
""")

result = cursor.fetchone()

if result:
    print("=" * 80)
    print("LATEST AI ANALYSIS DATA")
    print("=" * 80)
    print(f"ID: {result['id']}")
    print(f"Timestamp: {result['timestamp']}")
    print(f"Threat Level: {result['threat_level']}")
    print(f"Health Score: {result['network_health_score']}")
    print(f"\nSummary: {result['summary']}")
    
    print("\n" + "-" * 80)
    print("THREATS DETECTED:")
    print("-" * 80)
    if result['threats_detected']:
        threats = json.loads(result['threats_detected'])
        if threats:
            for i, threat in enumerate(threats, 1):
                print(f"\n{i}. {threat.get('category', 'Unknown')}")
                print(f"   Severity: {threat.get('severity', 'Unknown')}")
                print(f"   Description: {threat.get('description', 'N/A')[:100]}...")
        else:
            print("✓ No threats detected")
    
    print("\n" + "-" * 80)
    print("NETWORK INSIGHTS:")
    print("-" * 80)
    if result['network_insights']:
        insights = json.loads(result['network_insights'])
        print(f"Traffic Volume: {insights.get('total_traffic_volume', 'N/A')}")
        print(f"Protocols: {insights.get('most_active_protocols', [])}")
        print(f"Suspicious Connections: {insights.get('suspicious_connections', 0)}")
        print(f"Unusual Patterns: {insights.get('unusual_patterns', [])}")
    
    print("\n" + "-" * 80)
    print("DEVICE ANALYSIS:")
    print("-" * 80)
    if result['device_analysis']:
        devices = json.loads(result['device_analysis'])
        print(f"Total Devices: {devices.get('total_devices', 0)}")
        print(f"IoT Devices: {devices.get('iot_devices', 0)}")
        print(f"Suspicious Devices: {devices.get('suspicious_devices', [])}")
    
else:
    print("❌ No AI analysis data found in database!")
    print("\nPossible reasons:")
    print("1. AI aggregator hasn't run yet")
    print("2. API key issues")
    print("3. No network data to analyze")
    print("\nTry running: python3 /home/jarvis/NetGuard/scripts/ai_5min_aggregator.py")

conn.close()

