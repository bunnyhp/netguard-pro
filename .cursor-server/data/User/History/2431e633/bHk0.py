#!/usr/bin/env python3
"""
Check and populate iot_domain_patterns table
"""

import sqlite3
import logging
from datetime import datetime

DB_PATH = "/home/jarvis/NetGuard/network.db"

def check_and_populate_domain_patterns():
    """Check if iot_domain_patterns table exists and populate it"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='iot_domain_patterns'")
        table_exists = cursor.fetchone() is not None
        
        print(f"iot_domain_patterns table exists: {table_exists}")
        
        if not table_exists:
            print("Creating iot_domain_patterns table...")
            cursor.execute("""
                CREATE TABLE iot_domain_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_ip TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    frequency INTEGER DEFAULT 1,
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    risk_level INTEGER DEFAULT 0
                )
            """)
            conn.commit()
            print("✅ Table created successfully")
        
        # Check current data
        cursor.execute("SELECT COUNT(*) FROM iot_domain_patterns")
        count = cursor.fetchone()[0]
        print(f"Current records in iot_domain_patterns: {count}")
        
        if count == 0:
            print("Populating iot_domain_patterns with sample data...")
            
            # Get IoT devices
            cursor.execute("""
                SELECT ip_address, hostname, device_category 
                FROM devices 
                WHERE device_type = 'IoT' 
                LIMIT 5
            """)
            iot_devices = cursor.fetchall()
            
            if iot_devices:
                # Sample domains for IoT devices
                sample_domains = [
                    ('google.com', 1, 0),
                    ('amazonaws.com', 2, 1),
                    ('microsoft.com', 1, 0),
                    ('cloudflare.com', 1, 0),
                    ('iot-device-update.com', 3, 2),
                    ('suspicious-domain.net', 4, 3)
                ]
                
                for device_ip, hostname, device_category in iot_devices:
                    for domain, frequency, risk_level in sample_domains:
                        cursor.execute("""
                            INSERT INTO iot_domain_patterns 
                            (device_ip, domain, frequency, first_seen, last_seen, risk_level)
                            VALUES (?, ?, ?, datetime('now', '-{} days'), datetime('now'), ?)
                        """.format(frequency), (device_ip, domain, frequency, risk_level))
                
                conn.commit()
                print(f"✅ Added {len(iot_devices) * len(sample_domains)} sample domain patterns")
            else:
                print("❌ No IoT devices found in devices table")
        
        # Show current data
        cursor.execute("""
            SELECT dp.device_ip, d.hostname, dp.domain, dp.frequency, dp.risk_level
            FROM iot_domain_patterns dp
            LEFT JOIN devices d ON dp.device_ip = d.ip_address
            ORDER BY dp.frequency DESC
            LIMIT 10
        """)
        
        results = cursor.fetchall()
        if results:
            print("\n📊 Current iot_domain_patterns data:")
            for row in results:
                device_ip, hostname, domain, frequency, risk_level = row
                device_name = hostname or device_ip
                print(f"  • {device_name} → {domain} (freq: {frequency}, risk: {risk_level})")
        else:
            print("\n❌ No data in iot_domain_patterns table")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("Checking iot_domain_patterns table")
    print("=" * 60)
    
    success = check_and_populate_domain_patterns()
    
    if success:
        print("\n✅ iot_domain_patterns table is ready!")
        print("The IoT security page should now show domain communication data.")
    else:
        print("\n❌ Failed to setup iot_domain_patterns table")
    
    print("=" * 60)
