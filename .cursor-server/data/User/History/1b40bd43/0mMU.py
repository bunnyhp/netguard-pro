#!/usr/bin/env python3
"""
NetGuard Pro - API Key Setup Helper
Interactive script to add AI API keys
"""

import sqlite3
import sys

DB_PATH = "/home/jarvis/NetGuard/network.db"

def print_header():
    print("=" * 60)
    print("🔑 NetGuard Pro - AI API Key Setup")
    print("=" * 60)
    print()

def print_info():
    print("📝 You need at least ONE API key (all are FREE):")
    print()
    print("1. 🥇 Gemini (Primary - Recommended)")
    print("   Get key: https://aistudio.google.com/app/apikey")
    print()
    print("2. 🥈 Groq (Fallback - Fast)")
    print("   Get key: https://console.groq.com/keys")
    print()
    print("3. 🥉 OpenRouter (Optional - Many models)")
    print("   Get key: https://openrouter.ai/keys")
    print()
    print("Tip: Add all 3 for best reliability!")
    print()

def get_current_keys():
    """Get current API key status"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT key, value, description 
        FROM ai_config 
        WHERE key LIKE '%api_key%'
    """)
    
    keys = {}
    for row in cursor.fetchall():
        key_name = row[0]
        value = row[1]
        description = row[2]
        keys[key_name] = {
            'value': value,
            'set': value != 'YOUR_API_KEY_HERE',
            'description': description
        }
    
    conn.close()
    return keys

def display_status(keys):
    """Display current API key status"""
    print("=" * 60)
    print("📊 Current API Key Status:")
    print("=" * 60)
    
    for key_name, info in keys.items():
        status = "✅ SET" if info['set'] else "❌ NOT SET"
        print(f"{info['description']}: {status}")
    
    print()

def set_api_key(key_name, api_key):
    """Set API key in database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        UPDATE ai_config 
        SET value = ? 
        WHERE key = ?
    """, (api_key, key_name))
    
    conn.commit()
    conn.close()

def interactive_setup():
    """Interactive API key setup"""
    print_header()
    print_info()
    
    # Get current status
    keys = get_current_keys()
    display_status(keys)
    
    print("=" * 60)
    print("🔧 Setup API Keys")
    print("=" * 60)
    print("(Press Enter to skip any key)")
    print()
    
    # Gemini
    print("1️⃣  Gemini API Key (Primary):")
    if keys['gemini_api_key']['set']:
        print(f"   Current: {keys['gemini_api_key']['value'][:20]}...")
        replace = input("   Replace? (y/N): ").strip().lower()
        if replace != 'y':
            print("   ✓ Keeping current key")
        else:
            new_key = input("   Enter new key: ").strip()
            if new_key:
                set_api_key('gemini_api_key', new_key)
                print("   ✅ Gemini key updated!")
    else:
        new_key = input("   Enter Gemini API key: ").strip()
        if new_key:
            set_api_key('gemini_api_key', new_key)
            print("   ✅ Gemini key saved!")
        else:
            print("   ⏭️  Skipped")
    
    print()
    
    # Groq
    print("2️⃣  Groq API Key (Fallback):")
    if keys['groq_api_key']['set']:
        print(f"   Current: {keys['groq_api_key']['value'][:20]}...")
        replace = input("   Replace? (y/N): ").strip().lower()
        if replace != 'y':
            print("   ✓ Keeping current key")
        else:
            new_key = input("   Enter new key: ").strip()
            if new_key:
                set_api_key('groq_api_key', new_key)
                print("   ✅ Groq key updated!")
    else:
        new_key = input("   Enter Groq API key: ").strip()
        if new_key:
            set_api_key('groq_api_key', new_key)
            print("   ✅ Groq key saved!")
        else:
            print("   ⏭️  Skipped")
    
    print()
    
    # OpenRouter
    print("3️⃣  OpenRouter API Key (Optional):")
    if keys['openrouter_api_key']['set']:
        print(f"   Current: {keys['openrouter_api_key']['value'][:20]}...")
        replace = input("   Replace? (y/N): ").strip().lower()
        if replace != 'y':
            print("   ✓ Keeping current key")
        else:
            new_key = input("   Enter new key: ").strip()
            if new_key:
                set_api_key('openrouter_api_key', new_key)
                print("   ✅ OpenRouter key updated!")
    else:
        new_key = input("   Enter OpenRouter API key: ").strip()
        if new_key:
            set_api_key('openrouter_api_key', new_key)
            print("   ✅ OpenRouter key saved!")
        else:
            print("   ⏭️  Skipped")
    
    print()
    
    # Final status
    keys = get_current_keys()
    keys_set = sum(1 for k in keys.values() if k['set'])
    
    print("=" * 60)
    print("✅ Setup Complete!")
    print("=" * 60)
    print(f"API Keys Set: {keys_set}/3")
    print()
    
    if keys_set > 0:
        # Enable AI
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE ai_config SET value='1' WHERE key='ai_enabled';")
        conn.commit()
        conn.close()
        
        print("✓ AI analysis enabled")
        print()
        print("🚀 Test your setup:")
        print("   cd /home/jarvis/NetGuard")
        print("   python3 scripts/ai_service_connector.py")
        print()
        print("🌐 View results:")
        print("   http://192.168.1.161:8080/ai-dashboard")
    else:
        print("⚠️  No API keys set. AI analysis will not work.")
        print()
        print("Get free API keys:")
        print("   Gemini: https://aistudio.google.com/app/apikey")
        print("   Groq:   https://console.groq.com/keys")
        print("   OpenRouter: https://openrouter.ai/keys")
    
    print()

def command_line_mode():
    """Command-line mode for scripting"""
    if len(sys.argv) < 3:
        print("Usage: python3 setup_api_keys.py <provider> <api_key>")
        print("Providers: gemini, groq, openrouter")
        sys.exit(1)
    
    provider = sys.argv[1].lower()
    api_key = sys.argv[2]
    
    key_map = {
        'gemini': 'gemini_api_key',
        'groq': 'groq_api_key',
        'openrouter': 'openrouter_api_key'
    }
    
    if provider not in key_map:
        print(f"Unknown provider: {provider}")
        print("Valid providers: gemini, groq, openrouter")
        sys.exit(1)
    
    set_api_key(key_map[provider], api_key)
    print(f"✅ {provider.capitalize()} API key saved!")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        command_line_mode()
    else:
        interactive_setup()

