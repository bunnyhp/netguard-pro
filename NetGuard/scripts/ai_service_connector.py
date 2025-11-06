#!/usr/bin/env python3
"""
NetGuard Pro - Multi-AI Service Connector
Supports multiple free AI APIs with automatic fallback
Primary: Google Gemini 2.0 Flash
Fallbacks: Groq, OpenRouter (DeepSeek, Qwen, etc.)
"""

import json
import sqlite3
import logging
import re
from datetime import datetime
from ai_data_exporter import export_to_ai_format

DB_PATH = "/home/jarvis/NetGuard/network.db"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


class MultiAIAnalyzer:
    """
    Multi-provider AI analyzer with automatic fallback
    Supports: Gemini, Groq, OpenRouter (DeepSeek, Qwen)
    """
    
    def __init__(self, config):
        self.config = config
        self.models = self._load_model_configs()
        
    def _load_model_configs(self):
        """Load AI model configurations in priority order"""
        return [
            # PRIMARY: Google Gemini 2.0 Flash
            {
                'name': 'Gemini 2.0 Flash',
                'provider': 'gemini',
                'model': 'gemini-2.0-flash-exp',
                'api_key_name': 'gemini_api_key',
                'priority': 1,
                'enabled': True
            },
            
            # FALLBACK 1: Groq Llama 3.3 70B
            {
                'name': 'Groq Llama 3.3 70B',
                'provider': 'groq',
                'model': 'llama-3.3-70b-versatile',
                'api_key_name': 'groq_api_key',
                'priority': 2,
                'enabled': True
            },
            
            # FALLBACK 2: Groq Kimi K2
            {
                'name': 'Groq Kimi K2',
                'provider': 'groq',
                'model': 'kimi-k2',
                'api_key_name': 'groq_api_key',
                'priority': 3,
                'enabled': True
            },
            
            # FALLBACK 3: OpenRouter DeepSeek R1
            {
                'name': 'DeepSeek R1 (Qwen 8B)',
                'provider': 'openrouter',
                'model': 'deepseek/deepseek-r1-0528-qwen3-8b',
                'api_key_name': 'openrouter_api_key',
                'priority': 4,
                'enabled': True
            },
            
            # FALLBACK 4: OpenRouter Qwen Coder 480B
            {
                'name': 'Qwen 3 Coder 480B',
                'provider': 'openrouter',
                'model': 'qwen/qwen-3-coder-480b',
                'api_key_name': 'openrouter_api_key',
                'priority': 5,
                'enabled': True
            },
            
            # FALLBACK 5: OpenRouter DeepSeek V3.1
            {
                'name': 'DeepSeek V3.1',
                'provider': 'openrouter',
                'model': 'deepseek/deepseek-v3-1',
                'api_key_name': 'openrouter_api_key',
                'priority': 6,
                'enabled': True
            },
            
            # FALLBACK 6: Groq Llama 3.1 70B
            {
                'name': 'Groq Llama 3.1 70B',
                'provider': 'groq',
                'model': 'llama-3.1-70b-versatile',
                'api_key_name': 'groq_api_key',
                'priority': 7,
                'enabled': True
            },
            
            # FALLBACK 7: OpenRouter Llama 3.1 405B
            {
                'name': 'Meta Llama 3.1 405B',
                'provider': 'openrouter',
                'model': 'meta-llama/llama-3.1-405b',
                'api_key_name': 'openrouter_api_key',
                'priority': 8,
                'enabled': True
            }
        ]
    
    def analyze_network_data(self, network_data):
        """
        Analyze network data using available AI models
        Tries each model in priority order until success
        """
        
        logging.info(f"Starting AI analysis with {len(self.models)} available models")
        
        for model_config in self.models:
            if not model_config['enabled']:
                continue
                
            # Get API key from config
            api_key = self.config.get(model_config['api_key_name'])
            
            if not api_key or api_key == 'YOUR_API_KEY_HERE':
                logging.debug(f"⏭️  Skipping {model_config['name']} (no API key)")
                continue
            
            try:
                logging.info(f"🤖 Trying {model_config['name']}...")
                
                # Call appropriate provider
                if model_config['provider'] == 'gemini':
                    result = self._call_gemini(network_data, model_config, api_key)
                elif model_config['provider'] == 'groq':
                    result = self._call_groq(network_data, model_config, api_key)
                elif model_config['provider'] == 'openrouter':
                    result = self._call_openrouter(network_data, model_config, api_key)
                else:
                    logging.warning(f"Unknown provider: {model_config['provider']}")
                    continue
                
                if result:
                    logging.info(f"✅ Success with {model_config['name']}!")
                    result['ai_model_used'] = model_config['name']
                    return result
                    
            except Exception as e:
                logging.warning(f"❌ {model_config['name']} failed: {str(e)[:100]}")
                continue
        
        logging.error("❌ All AI models failed or no API keys configured")
        return None
    
    def _call_gemini(self, data, config, api_key):
        """Call Google Gemini API"""
        try:
            import google.generativeai as genai
        except ImportError:
            logging.error("google-generativeai not installed. Run: pip install google-generativeai")
            return None
        
        try:
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel(config['model'])
            
            prompt = self._build_prompt(data)
            
            response = model.generate_content(
                prompt,
                generation_config={
                    'temperature': 0.3,
                    'max_output_tokens': 4096,
                }
            )
            
            return self._parse_json_response(response.text)
            
        except Exception as e:
            logging.error(f"Gemini error: {e}")
            return None
    
    def _call_groq(self, data, config, api_key):
        """Call Groq API (Llama, Kimi, etc.)"""
        try:
            from groq import Groq
        except ImportError:
            logging.error("groq not installed. Run: pip install groq")
            return None
        
        try:
            client = Groq(api_key=api_key)
            
            response = client.chat.completions.create(
                model=config['model'],
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert network security analyst. Analyze network traffic and identify threats. Always respond with valid JSON only."
                    },
                    {
                        "role": "user",
                        "content": self._build_prompt(data)
                    }
                ],
                temperature=0.3,
                max_tokens=4096,
                response_format={"type": "json_object"}
            )
            
            json_text = response.choices[0].message.content
            return self._parse_json_response(json_text)
            
        except Exception as e:
            logging.error(f"Groq error: {e}")
            return None
    
    def _call_openrouter(self, data, config, api_key):
        """Call OpenRouter API (DeepSeek, Qwen, etc.)"""
        try:
            from openai import OpenAI
        except ImportError:
            logging.error("openai not installed. Run: pip install openai")
            return None
        
        try:
            client = OpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=api_key
            )
            
            response = client.chat.completions.create(
                model=config['model'],
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert network security analyst. Analyze network traffic and identify threats. Always respond with valid JSON only."
                    },
                    {
                        "role": "user",
                        "content": self._build_prompt(data)
                    }
                ],
                temperature=0.3,
                max_tokens=4096
            )
            
            json_text = response.choices[0].message.content
            return self._parse_json_response(json_text)
            
        except Exception as e:
            logging.error(f"OpenRouter error: {e}")
            return None
    
    def _build_prompt(self, network_data):
        """Build analysis prompt for AI"""
        
        metrics = network_data.get('network_metrics', {})
        devices = network_data.get('devices', [])
        connections = network_data.get('connections', [])
        dns_queries = network_data.get('dns_queries', [])
        http_traffic = network_data.get('http_traffic', [])
        
        prompt = f"""You are a network security expert analyzing home network traffic for threats.

**Network Data Summary:**
- Total Packets: {metrics.get('total_packets', 0)}
- Total Bytes: {metrics.get('total_bytes', 0)}
- Unique Source IPs: {metrics.get('unique_src_ips', 0)}
- Unique Destination IPs: {metrics.get('unique_dst_ips', 0)}
- Protocol Distribution: {json.dumps(metrics.get('protocol_distribution', {}))}
- Active Devices: {len(devices)}
- Active Connections: {len(connections)}
- DNS Queries: {len(dns_queries)}
- HTTP Requests: {len(http_traffic)}

**Detailed Analysis Required:**

1. **Threat Detection:**
   - Port scans (20+ ports from same source)
   - DDoS patterns (1000+ packets/sec)
   - Botnet beacons (periodic connections)
   - Data exfiltration (large uploads to unknown IPs)
   - Brute force attempts (repeated failed connections)

2. **Anomaly Detection:**
   - Traffic volume spikes
   - Unusual protocols
   - Off-hours activity
   - Suspicious port usage

3. **URL/Domain Analysis:**
   - Phishing domains
   - DGA (Domain Generation Algorithm) patterns
   - Malware C&C servers
   - Typosquatting

**Full Network Data:**
```json
{json.dumps(network_data, indent=2)}
```

**RESPOND WITH ONLY VALID JSON IN THIS EXACT FORMAT (no markdown, no explanation):**

{{
  "analysis_timestamp": "{datetime.now().isoformat()}",
  "overall_threat_level": "LOW or MEDIUM or HIGH or CRITICAL",
  "network_health_score": 0-100,
  "threats_detected": [
    {{
      "threat_id": "THR-{datetime.now().strftime('%Y%m%d')}-001",
      "severity": "HIGH or MEDIUM or LOW",
      "confidence": 0.0-1.0,
      "threat_type": "Port Scan or DDoS or Malware or Botnet or Data Exfiltration",
      "source_ip": "x.x.x.x",
      "target_ip": "x.x.x.x",
      "description": "detailed explanation of the threat",
      "recommendation": "specific action to take",
      "indicators": ["list", "of", "threat", "indicators"]
    }}
  ],
  "device_anomalies": [
    {{
      "device_ip": "x.x.x.x",
      "device_name": "Device Name",
      "anomaly_score": 0.0-1.0,
      "anomaly_type": "Unusual Traffic Volume or Suspicious Protocol or Off-hours Activity",
      "baseline_deviation": 1.0-10.0,
      "description": "what is unusual about this device"
    }}
  ],
  "url_classifications": [
    {{
      "url": "http://example.com",
      "domain": "example.com",
      "risk_score": 0.0-1.0,
      "category": "Phishing or Malware or DGA or C&C or Safe",
      "threat_intel_match": true or false,
      "indicators": ["why this URL is risky"],
      "action": "BLOCK or WARN or ALLOW",
      "accessed_by": ["list of IPs that accessed it"]
    }}
  ],
  "behavior_patterns": [
    {{
      "pattern_type": "Botnet Beacon or Scanning Activity or Data Exfiltration",
      "confidence": 0.0-1.0,
      "device_ip": "x.x.x.x",
      "description": "description of the pattern",
      "characteristics": {{
        "interval": 60,
        "destination": "x.x.x.x",
        "port": 8443
      }}
    }}
  ],
  "dns_analysis": [
    {{
      "domain": "example.com",
      "classification": "DGA or Phishing or C&C or Safe",
      "risk_score": 0.0-1.0,
      "reason": "why this domain is flagged",
      "queried_by": ["list of IPs"]
    }}
  ],
  "alerts": [
    {{
      "alert_id": "ALT-{datetime.now().strftime('%Y%m%d')}-001",
      "priority": "CRITICAL or HIGH or MEDIUM or LOW",
      "title": "Short alert title",
      "message": "Detailed alert message for homeowner",
      "threat_type": "Port Scan or Malware or etc",
      "source_ip": "x.x.x.x",
      "confidence": 0.0-1.0,
      "indicators": ["list of indicators"],
      "recommended_action": "Specific action homeowner should take",
      "auto_block": true or false
    }}
  ],
  "statistics": {{
    "packets_analyzed": {metrics.get('total_packets', 0)},
    "threats_found": 0,
    "devices_monitored": {len(devices)},
    "urls_classified": {len(dns_queries)},
    "processing_time_ms": 100
  }}
}}

IMPORTANT: Return ONLY the JSON object. No markdown formatting, no explanations, just pure JSON.
"""
        
        return prompt
    
    def _parse_json_response(self, text):
        """Parse JSON from AI response (handles markdown code blocks)"""
        
        # Remove markdown code blocks if present
        text = text.strip()
        
        # Remove ```json and ``` markers
        if text.startswith('```'):
            text = re.sub(r'^```(?:json)?\s*\n', '', text)
            text = re.sub(r'\n```\s*$', '', text)
        
        # Try to parse JSON
        try:
            result = json.loads(text)
            return result
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse JSON response: {e}")
            logging.debug(f"Response text: {text[:500]}...")
            return None


def get_ai_config():
    """Load AI configuration from database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT key, value FROM ai_config")
    config = {row[0]: row[1] for row in cursor.fetchall()}
    conn.close()
    
    return config


def store_ai_predictions(ai_response):
    """Store AI analysis results in database"""
    if not ai_response:
        return False
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # Store main prediction
        cursor.execute("""
            INSERT INTO ai_predictions (
                timestamp, analysis_window, threat_level, network_health_score,
                threats_detected, anomalies_detected, alerts_generated,
                threats_json, anomalies_json, patterns_json, dns_analysis_json,
                processing_time_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ai_response.get('analysis_timestamp'),
            '5m',
            ai_response.get('overall_threat_level'),
            ai_response.get('network_health_score'),
            len(ai_response.get('threats_detected', [])),
            len(ai_response.get('device_anomalies', [])),
            len(ai_response.get('alerts', [])),
            json.dumps(ai_response.get('threats_detected', [])),
            json.dumps(ai_response.get('device_anomalies', [])),
            json.dumps(ai_response.get('behavior_patterns', [])),
            json.dumps(ai_response.get('dns_analysis', [])),
            ai_response.get('statistics', {}).get('processing_time_ms', 0)
        ))
        
        prediction_id = cursor.lastrowid
        
        # Store alerts
        for alert in ai_response.get('alerts', []):
            cursor.execute("""
                INSERT INTO ai_alerts (
                    alert_id, priority, title, message, threat_type,
                    source_ip, confidence, indicators, recommended_action,
                    auto_block, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.get('alert_id'),
                alert.get('priority'),
                alert.get('title'),
                alert.get('message'),
                alert.get('threat_type', 'Unknown'),
                alert.get('source_ip'),
                alert.get('confidence', 0.0),
                json.dumps(alert.get('indicators', [])),
                alert.get('recommended_action'),
                1 if alert.get('auto_block') else 0,
                datetime.now().isoformat()
            ))
        
        # Store URL classifications
        for url_data in ai_response.get('url_classifications', []):
            cursor.execute("""
                INSERT OR REPLACE INTO url_classifications (
                    url, domain, risk_score, category, threat_intel_match,
                    indicators, action, accessed_by, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                url_data.get('url'),
                url_data.get('domain'),
                url_data.get('risk_score'),
                url_data.get('category'),
                1 if url_data.get('threat_intel_match') else 0,
                json.dumps(url_data.get('indicators', [])),
                url_data.get('action'),
                json.dumps(url_data.get('accessed_by', [])),
                datetime.now().isoformat(),
                datetime.now().isoformat()
            ))
        
        # Store threat patterns
        for pattern in ai_response.get('behavior_patterns', []):
            cursor.execute("""
                INSERT INTO threat_patterns (
                    pattern_type, device_ip, confidence, description,
                    characteristics, first_detected, last_detected, severity
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                pattern.get('pattern_type'),
                pattern.get('device_ip'),
                pattern.get('confidence'),
                pattern.get('description'),
                json.dumps(pattern.get('characteristics', {})),
                datetime.now().isoformat(),
                datetime.now().isoformat(),
                'HIGH' if pattern.get('confidence', 0) > 0.8 else 'MEDIUM'
            ))
        
        # Store device anomalies as updates to device profiles
        for anomaly in ai_response.get('device_anomalies', []):
            device_ip = anomaly.get('device_ip')
            if device_ip:
                cursor.execute("""
                    INSERT OR REPLACE INTO device_profiles (
                        device_ip, device_name, last_updated
                    ) VALUES (?, ?, ?)
                """, (
                    device_ip,
                    anomaly.get('device_name', 'Unknown'),
                    datetime.now().isoformat()
                ))
        
        # Store analysis history
        cursor.execute("""
            INSERT INTO ai_analysis_history (
                timestamp, packets_analyzed, devices_analyzed,
                threats_found, alerts_generated, analysis_duration_ms, success
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().isoformat(),
            ai_response.get('statistics', {}).get('packets_analyzed', 0),
            ai_response.get('statistics', {}).get('devices_monitored', 0),
            ai_response.get('statistics', {}).get('threats_found', 0),
            len(ai_response.get('alerts', [])),
            ai_response.get('statistics', {}).get('processing_time_ms', 0),
            1
        ))
        
        conn.commit()
        
        model_used = ai_response.get('ai_model_used', 'Unknown')
        logging.info(f"✓ Stored AI results from {model_used}: "
                    f"{len(ai_response.get('alerts', []))} alerts, "
                    f"{len(ai_response.get('threats_detected', []))} threats")
        
        return True
        
    except Exception as e:
        logging.error(f"Error storing AI predictions: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()


def analyze_network():
    """Main function: Export data, send to AI, store results"""
    
    logging.info("=" * 60)
    logging.info("NetGuard Pro - Multi-AI Analysis Cycle")
    logging.info("=" * 60)
    
    # Get configuration
    config = get_ai_config()
    
    # Check if AI is enabled
    if config.get('ai_enabled', '0') == '0':
        logging.info("AI analysis is disabled in configuration")
        logging.info("Enable with: UPDATE ai_config SET value='1' WHERE key='ai_enabled';")
        return False
    
    # Export network data
    logging.info("Step 1: Exporting network data...")
    network_data = export_to_ai_format(time_window_minutes=5)
    
    if not network_data:
        logging.warning("No data to analyze")
        return False
    
    logging.info(f"✓ Exported {network_data['network_metrics']['total_packets']} packets")
    
    # Create AI analyzer
    analyzer = MultiAIAnalyzer(config)
    
    # Analyze with AI
    logging.info("Step 2: Analyzing with AI models...")
    ai_response = analyzer.analyze_network_data(network_data)
    
    if not ai_response:
        logging.warning("No response from any AI service")
        # Store failed attempt in history
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO ai_analysis_history (
                timestamp, packets_analyzed, success, error_message
            ) VALUES (?, ?, ?, ?)
        """, (
            datetime.now().isoformat(),
            network_data['network_metrics']['total_packets'],
            0,
            'All AI services unavailable or no API keys configured'
        ))
        conn.commit()
        conn.close()
        return False
    
    # Store results
    logging.info("Step 3: Storing AI predictions...")
    success = store_ai_predictions(ai_response)
    
    if success:
        logging.info("=" * 60)
        logging.info("✅ AI Analysis Complete!")
        logging.info(f"   Model Used: {ai_response.get('ai_model_used', 'Unknown')}")
        logging.info(f"   Threat Level: {ai_response.get('overall_threat_level')}")
        logging.info(f"   Health Score: {ai_response.get('network_health_score')}/100")
        logging.info(f"   Threats: {len(ai_response.get('threats_detected', []))}")
        logging.info(f"   Alerts: {len(ai_response.get('alerts', []))}")
        logging.info("=" * 60)
    
    return success


if __name__ == "__main__":
    # Run analysis
    success = analyze_network()
    
    if not success:
        logging.info("\nℹ️  Note: Configure API keys for AI analysis")
        logging.info("   See: /home/jarvis/NetGuard/API_KEY_SETUP.md")
        logging.info("   Or run: python3 /home/jarvis/NetGuard/scripts/setup_api_keys.py")
