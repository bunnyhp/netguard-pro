#!/usr/bin/env python3
import sqlite3

conn = sqlite3.connect("/home/jarvis/NetGuard/network.db")
cursor = conn.cursor()

cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'p0f_%' AND name NOT LIKE '%template%' ORDER BY name DESC LIMIT 10")
tables = cursor.fetchall()

print(f"P0F TABLES: {len(tables)}")
for t in tables:
    print(f"  - {t[0]}")
    cursor.execute(f"SELECT COUNT(*) FROM {t[0]}")
    count = cursor.fetchone()[0]
    print(f"    Records: {count}")

conn.close()

