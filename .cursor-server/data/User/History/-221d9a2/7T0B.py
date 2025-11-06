#!/usr/bin/env python3
"""
Test script to verify dashboard works correctly
"""

import sys
import sqlite3

DB_PATH = "/home/jarvis/NetGuard/network.db"

print("=" * 60)
print("NetGuard Dashboard Pre-Flight Check")
print("=" * 60)

# Test 1: Database connectivity
print("\n1. Testing database connectivity...")
try:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    print("   ✓ Database connection successful")
except Exception as e:
    print(f"   ✗ Database connection failed: {e}")
    sys.exit(1)

# Test 2: Check for devices table
print("\n2. Checking for devices table...")
try:
    cursor.execute("SELECT COUNT(*) FROM devices")
    count = cursor.fetchone()[0]
    print(f"   ✓ devices table exists ({count} devices)")
except Exception as e:
    print(f"   ⚠ devices table missing or error: {e}")
    print("   Creating devices table...")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            ip_address TEXT PRIMARY KEY,
            mac_address TEXT,
            hostname TEXT,
            vendor TEXT,
            device_type TEXT,
            device_category TEXT,
            security_score INTEGER DEFAULT 50,
            first_seen TEXT,
            last_seen TEXT
        )
    """)
    conn.commit()
    print("   ✓ devices table created")

# Test 3: Check for iot_vulnerabilities table
print("\n3. Checking for iot_vulnerabilities table...")
try:
    cursor.execute("SELECT COUNT(*) FROM iot_vulnerabilities")
    count = cursor.fetchone()[0]
    print(f"   ✓ iot_vulnerabilities table exists ({count} vulnerabilities)")
except Exception as e:
    print(f"   ⚠ iot_vulnerabilities table missing: {e}")
    print("   Creating iot_vulnerabilities table...")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS iot_vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_ip TEXT,
            vulnerability_type TEXT,
            severity TEXT,
            description TEXT,
            detected_at TEXT,
            resolved INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    print("   ✓ iot_vulnerabilities table created")

# Test 4: Check for ai_analysis table
print("\n4. Checking for ai_analysis table...")
try:
    cursor.execute("SELECT COUNT(*) FROM ai_analysis")
    count = cursor.fetchone()[0]
    print(f"   ✓ ai_analysis table exists ({count} analyses)")
except Exception as e:
    print(f"   ⚠ ai_analysis table missing: {e}")
    print("   Creating ai_analysis table...")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ai_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            threat_level TEXT,
            network_health_score INTEGER,
            threats_detected TEXT,
            network_insights TEXT,
            device_analysis TEXT,
            http_analysis TEXT,
            recommendations TEXT,
            iot_analysis TEXT
        )
    """)
    conn.commit()
    print("   ✓ ai_analysis table created")

# Test 5: Check for traffic tables
print("\n5. Checking for traffic data tables...")
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'tcpdump_%'")
tcpdump_tables = cursor.fetchall()
if tcpdump_tables:
    print(f"   ✓ Found {len(tcpdump_tables)} tcpdump tables")
else:
    print("   ⚠ No tcpdump tables found (waiting for collectors)")

# Test 6: List all tables
print("\n6. Available tables in database:")
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
tables = cursor.fetchall()
for table in tables:
    if not table[0].endswith('_template'):
        cursor.execute(f"SELECT COUNT(*) FROM {table[0]}")
        count = cursor.fetchone()[0]
        print(f"   - {table[0]}: {count} records")

conn.close()

print("\n" + "=" * 60)
print("Pre-Flight Check Complete!")
print("=" * 60)

# Test 7: Try to import Flask app
print("\n7. Testing Flask app import...")
sys.path.insert(0, '/home/jarvis/NetGuard/web')
try:
    import app
    print("   ✓ Flask app imported successfully")
except Exception as e:
    print(f"   ✗ Flask app import failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n✓ All checks passed! Dashboard should work correctly.")
print("\nTo start the dashboard:")
print("  cd /home/jarvis/NetGuard/web")
print("  python3 app.py")

