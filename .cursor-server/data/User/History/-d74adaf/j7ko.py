#!/usr/bin/env python3
import sqlite3
import json

conn = sqlite3.connect("/home/jarvis/NetGuard/network.db")
cursor = conn.cursor()

# Get all p0f tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'p0f_%' AND name NOT LIKE '%template%' ORDER BY name DESC")
tables = cursor.fetchall()

print(f"=== P0F TABLES: {len(tables)} ===\n")

for table_name in tables:
    table = table_name[0]
    print(f"TABLE: {table}")
    
    # Get record count
    cursor.execute(f"SELECT COUNT(*) FROM {table}")
    count = cursor.fetchone()[0]
    print(f"Records: {count}\n")
    
    # Get all data
    cursor.execute(f"SELECT * FROM {table} LIMIT 10")
    rows = cursor.fetchall()
    
    # Get column names
    cursor.execute(f"PRAGMA table_info({table})")
    columns = [col[1] for col in cursor.fetchall()]
    
    print(f"Columns: {', '.join(columns)}\n")
    
    for i, row in enumerate(rows, 1):
        print(f"Record {i}:")
        for col, val in zip(columns, row):
            print(f"  {col}: {val}")
        print()

conn.close()

