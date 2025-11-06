#!/usr/bin/env python3
"""
Test script to check IoT devices route
"""

import sys
import os
sys.path.append('/home/jarvis/NetGuard/web')

try:
    from app import app
    import sqlite3
    
    print("Testing IoT devices route...")
    
    # Test database connection
    DB_PATH = "/home/jarvis/NetGuard/network.db"
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check if devices table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='devices'")
    devices_exists = cursor.fetchone() is not None
    print(f"Devices table exists: {devices_exists}")
    
    if devices_exists:
        cursor.execute("SELECT COUNT(*) FROM devices")
        device_count = cursor.fetchone()[0]
        print(f"Total devices: {device_count}")
        
        cursor.execute("SELECT COUNT(*) FROM devices WHERE device_type = 'IoT'")
        iot_count = cursor.fetchone()[0]
        print(f"IoT devices: {iot_count}")
    
    conn.close()
    
    # Test the route with Flask test client
    with app.test_client() as client:
        response = client.get('/iot-devices')
        print(f"Response status: {response.status_code}")
        if response.status_code != 200:
            print(f"Error response: {response.data.decode()}")
        else:
            print("IoT devices route working!")
    
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
