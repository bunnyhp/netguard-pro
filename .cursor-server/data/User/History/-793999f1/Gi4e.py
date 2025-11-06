#!/usr/bin/env python3
"""
Diagnose Network Traffic Analysis issue
"""

import requests
import json

def diagnose_traffic_issue():
    print("=" * 60)
    print("DIAGNOSING NETWORK TRAFFIC ANALYSIS ISSUE")
    print("=" * 60)
    
    # Test 1: Check if Flask is running
    try:
        response = requests.get('http://localhost:8080/', timeout=5)
        print(f"✅ Flask is running (HTTP {response.status_code})")
    except Exception as e:
        print(f"❌ Flask is not running: {e}")
        return
    
    # Test 2: Check IoT devices page
    try:
        response = requests.get('http://localhost:8080/iot-devices', timeout=5)
        print(f"✅ IoT Devices page accessible (HTTP {response.status_code})")
    except Exception as e:
        print(f"❌ IoT Devices page error: {e}")
        return
    
    # Test 3: Check Network Traffic API
    try:
        response = requests.get('http://localhost:8080/api/network-traffic-stats', timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Network Traffic API working:")
            print(f"   Total Traffic: {data.get('total_traffic_mb', 0)} MB")
            print(f"   Peak Rate: {data.get('peak_rate_mbps', 0)} Mbps")
            print(f"   Suspicious: {data.get('suspicious_count', 0)}")
            print(f"   Encrypted: {data.get('encrypted_percentage', 0)}%")
        else:
            print(f"❌ Network Traffic API error: HTTP {response.status_code}")
    except Exception as e:
        print(f"❌ Network Traffic API error: {e}")
    
    # Test 4: Check Domain Communications API
    try:
        response = requests.get('http://localhost:8080/api/domain-communications', timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Domain Communications API working ({len(data)} items)")
        else:
            print(f"❌ Domain Communications API error: HTTP {response.status_code}")
    except Exception as e:
        print(f"❌ Domain Communications API error: {e}")
    
    # Test 5: Check Attack Monitoring API
    try:
        response = requests.get('http://localhost:8080/api/attack-monitoring', timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Attack Monitoring API working ({data.get('total_attacks', 0)} attacks)")
        else:
            print(f"❌ Attack Monitoring API error: HTTP {response.status_code}")
    except Exception as e:
        print(f"❌ Attack Monitoring API error: {e}")
    
    print("\n" + "=" * 60)
    print("DIAGNOSIS COMPLETE")
    print("=" * 60)
    print("\n🔍 NEXT STEPS:")
    print("1. Open browser Developer Tools (F12)")
    print("2. Go to Console tab")
    print("3. Visit: http://localhost:8080/iot-devices")
    print("4. Look for debug messages:")
    print("   - 'IoT Security Page: Initializing...'")
    print("   - 'Loading traffic data...'")
    print("   - 'Traffic chart updated successfully'")
    print("5. Check for any JavaScript errors in red")
    print("\n🌐 Test page: http://localhost:8080/static/TEST_TRAFFIC_JS.html")

if __name__ == "__main__":
    diagnose_traffic_issue()
