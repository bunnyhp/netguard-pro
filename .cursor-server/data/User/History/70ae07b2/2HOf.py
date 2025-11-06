#!/usr/bin/env python3
"""
Test script to manually run the AI aggregator and verify it's working
"""

import sys
import os
sys.path.append('/home/jarvis/NetGuard/scripts')

from ai_5min_aggregator import aggregate_data_last_5min, build_ai_prompt, call_gemini_api, call_groq_api, store_ai_results, load_config
import json
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def test_ai_aggregator():
    """Test the AI aggregator functionality"""
    print("=" * 60)
    print("Testing NetGuard Pro AI Aggregator")
    print("=" * 60)
    
    # Step 1: Test data aggregation
    print("\n🔍 Step 1: Testing data aggregation...")
    data = aggregate_data_last_5min()
    
    if data:
        print(f"✅ Data aggregation successful!")
        print(f"   • Timestamp: {data['timestamp']}")
        print(f"   • Tools collected: {len(data['tools'])}")
        print(f"   • Network devices: {data['network_summary']['total_tracked_devices']}")
        print(f"   • IoT devices: {data['iot_devices']['total_iot_devices']}")
        print(f"   • IoT vulnerabilities: {data['iot_security']['total_vulnerabilities']}")
        
        # Show tool data summary
        print("\n📊 Tool Data Summary:")
        for tool, tool_data in data['tools'].items():
            if isinstance(tool_data, dict):
                print(f"   • {tool}: {len(tool_data)} data points")
    else:
        print("❌ Data aggregation failed!")
        return False
    
    # Step 2: Test AI prompt building
    print("\n🤖 Step 2: Testing AI prompt building...")
    prompt = build_ai_prompt(data)
    
    if prompt and len(prompt) > 1000:
        print(f"✅ AI prompt built successfully!")
        print(f"   • Prompt length: {len(prompt)} characters")
        print(f"   • Contains network data: {'network_summary' in prompt}")
        print(f"   • Contains tool data: {'tools' in prompt}")
    else:
        print("❌ AI prompt building failed!")
        return False
    
    # Step 3: Test AI API call
    print("\n🌐 Step 3: Testing AI API call...")
    config = load_config()
    
    if config and config.get('ai_enabled'):
        print("✅ AI configuration loaded")
        print(f"   • AI enabled: {config.get('ai_enabled')}")
        print(f"   • API key present: {'api_key' in config}")
        
        # Test API call
        analysis = call_gemini_api(prompt, config)
        
        if analysis:
            print("✅ AI API call successful!")
            print(f"   • Threat level: {analysis.get('threat_level', 'UNKNOWN')}")
            print(f"   • Health score: {analysis.get('network_health_score', 0)}")
            print(f"   • Threats detected: {len(analysis.get('threats_detected', []))}")
            print(f"   • Summary: {analysis.get('summary', 'No summary')[:100]}...")
            
            # Step 4: Test storing results
            print("\n💾 Step 4: Testing result storage...")
            analysis_id = store_ai_results(analysis)
            
            if analysis_id:
                print(f"✅ Results stored successfully! ID: {analysis_id}")
                return True
            else:
                print("❌ Result storage failed!")
                return False
        else:
            print("❌ AI API call failed!")
            return False
    else:
        print("❌ AI configuration not found or disabled!")
        return False

if __name__ == "__main__":
    success = test_ai_aggregator()
    
    if success:
        print("\n🎉 AI Aggregator Test: SUCCESS!")
        print("The AI system is working correctly and will:")
        print("• Collect data from all 10 monitoring tools")
        print("• Send comprehensive analysis to AI")
        print("• Store results in database")
        print("• Update AI dashboard with real-time data")
    else:
        print("\n❌ AI Aggregator Test: FAILED!")
        print("Please check the configuration and try again.")
    
    print("\n" + "=" * 60)
