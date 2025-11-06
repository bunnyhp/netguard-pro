#!/usr/bin/env python3
import sqlite3
import os

DB_PATH = "/home/jarvis/NetGuard/network.db"

print("="*60)
print("P0F DATABASE CHECK")
print("="*60)

if not os.path.exists(DB_PATH):
    print(f"ERROR: Database not found at {DB_PATH}")
    exit(1)

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Get all p0f tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'p0f_%' ORDER BY name DESC")
tables = cursor.fetchall()

print(f"\nFound {len(tables)} p0f tables:")
print("-" * 60)

if len(tables) == 0:
    print("✗ NO P0F TABLES FOUND IN DATABASE")
    print("\nThis means p0f_collector.py is NOT inserting data.")
    print("\nPossible reasons:")
    print("1. p0f log file is empty (no traffic captured)")
    print("2. p0f_collector.py is not running properly")
    print("3. p0f_collector.py has errors parsing the log")
else:
    for table in tables[:10]:  # Show last 10 tables
        table_name = table[0]
        cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
        count = cursor.fetchone()[0]
        
        # Get sample data
        if count > 0:
            cursor.execute(f"SELECT * FROM {table_name} LIMIT 1")
            sample = cursor.fetchone()
            print(f"\n✓ {table_name}: {count} records")
            if sample:
                cursor.execute(f"PRAGMA table_info({table_name})")
                columns = [col[1] for col in cursor.fetchall()]
                print(f"  Columns: {', '.join(columns)}")
                print(f"  Sample: {dict(zip(columns, sample))}")
        else:
            print(f"\n✗ {table_name}: EMPTY (0 records)")

conn.close()

print("\n" + "="*60)
print("SUMMARY")
print("="*60)
print(f"Total p0f tables: {len(tables)}")
if len(tables) > 0:
    cursor = sqlite3.connect(DB_PATH).cursor()
    cursor.execute(f"SELECT SUM(cnt) FROM (SELECT COUNT(*) as cnt FROM {tables[0][0]} UNION ALL SELECT 0)")
    total_records = sum([cursor.execute(f"SELECT COUNT(*) FROM {t[0]}").fetchone()[0] for t in tables])
    print(f"Total records: {total_records}")
else:
    print("Total records: 0")
print("="*60)

