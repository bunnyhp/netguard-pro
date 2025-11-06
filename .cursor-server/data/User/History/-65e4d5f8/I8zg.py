#!/usr/bin/env python3
"""
Quick script to clear only AI analysis data
"""
import sqlite3

DB_PATH = "/home/jarvis/NetGuard/network.db"

print("Clearing AI analysis table...")

try:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Clear AI analysis
    cursor.execute("DELETE FROM ai_analysis")
    rows_deleted = cursor.rowcount
    
    conn.commit()
    conn.close()
    
    print(f"✓ Cleared {rows_deleted} old AI analysis entries")
    print("\nThe AI dashboard will now show 'No data' until the next 5-minute analysis cycle.")
    print("New analysis will be generated with filtered data (no Ethertype alerts).")
    
except Exception as e:
    print(f"✗ Error: {e}")

