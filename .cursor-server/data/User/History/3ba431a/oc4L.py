#!/usr/bin/env python3
"""
Test the network traffic API endpoint
"""

import requests
import json

def test_traffic_api():
    try:
        print("Testing Network Traffic API...")
        
        # Test the API endpoint
        response = requests.get('http://localhost:8080/api/network-traffic-stats')
        
        if response.status_code == 200:
            data = response.json()
            print("✅ API Response:")
            print(f"  Total Traffic: {data.get('total_traffic_mb', 0)} MB")
            print(f"  Peak Rate: {data.get('peak_rate_mbps', 0)} Mbps")
            print(f"  Suspicious: {data.get('suspicious_count', 0)}")
            print(f"  Encrypted: {data.get('encrypted_percentage', 0)}%")
            return True
        else:
            print(f"❌ API Error: HTTP {response.status_code}")
            print(response.text)
            return False
            
    except Exception as e:
        print(f"❌ Connection Error: {e}")
        return False

if __name__ == "__main__":
    test_traffic_api()
