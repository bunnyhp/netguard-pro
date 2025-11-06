#!/usr/bin/env python3
"""
NetGuard Pro - AI Connector v2
Uses JSON config file and comprehensive data from all tools
"""

import json
import sqlite3
import logging
import re
from datetime import datetime
from comprehensive_data_aggregator import aggregate_all_data, export_for_ai, load_config

DB_PATH = "/home/jarvis/NetGuard/network.db"
CONFIG_PATH = "/home/jarvis/NetGuard/config/ai_config.json"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


class MultiAIAnalyzer:
    """Multi-provider AI analyzer with automatic fallback"""
    
    def __init__(self, config):
        self.config = config
        self.api_keys = config.get('api_keys', {})
        self.models = self._load_model_configs()
        
    def _load_model_configs(self):
        """Load AI model configurations"""
        return [
            {
                'name': 'Gemini 2.0 Flash',
                'provider': 'gemini',
                'model': 'gemini-2.0-flash-exp',
                'api_key': self.api_keys.get('gemini_api_key'),
                'priority': 1
            },
            {
                'name': 'Groq Llama 3.3 70B',
                'provider': 'groq',
                'model': 'llama-3.3-70b-versatile',
                'api_key': self.api_keys.get('groq_api_key'),
                'priority': 2
            },
            {
                'name': 'OpenRouter DeepSeek R1',
                'provider': 'openrouter',
                'model': 'deepseek/deepseek-r1',
                'api_key': self.api_keys.get('openrouter_api_key'),
                'priority': 3
            }
        ]
    
    def analyze_network_data(self, data):
        """Analyze comprehensive network data with AI"""
        
        logging.info(f"Starting AI analysis with {len(self.models)} available models")
        
        for model_config in self.models:
            api_key = model_config.get('api_key')
            
            if not api_key or api_key == 'YOUR_GEMINI_KEY_HERE' or api_key == 'YOUR_GROQ_KEY_HERE' or api_key == 'YOUR_OPENROUTER_KEY_HERE':
                logging.debug(f"⏭️  Skipping {model_config['name']} (no API key)")
                continue
            
            try:
                logging.info(f"🤖 Trying {model_config['name']}...")
                
                if model_config['provider'] == 'gemini':
                    result = self._call_gemini(data, model_config, api_key)
                elif model_config['provider'] == 'groq':
                    result = self._call_groq(data, model_config, api_key)
                elif model_config['provider'] == 'openrouter':
                    result = self._call_openrouter(data, model_config, api_key)
                else:
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
            logging.error("google-generativeai not installed")
            return None
        
        try:
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel(config['model'])
            
            prompt = self._build_comprehensive_prompt(data)
            
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
        """Call Groq API"""
        try:
            from groq import Groq
        except ImportError:
            logging.error("groq not installed")
            return None
        
        try:
            client = Groq(api_key=api_key)
            
            response = client.chat.completions.create(
                model=config['model'],
                messages=[
                    {"role": "system", "content": "You are an expert network security analyst. Analyze network traffic and identify threats. Always respond with valid JSON only."},
                    {"role": "user", "content": self._build_comprehensive_prompt(data)}
                ],
                temperature=0.3,
                max_tokens=4096,
                response_format={"type": "json_object"}
            )
            
            return self._parse_json_response(response.choices[0].message.content)
            
        except Exception as e:
            logging.error(f"Groq error: {e}")
            return None
    
    def _call_openrouter(self, data, config, api_key):
        """Call OpenRouter API"""
        try:
            from openai import OpenAI
        except ImportError:
            logging.error("openai not installed")
            return None
        
        try:
            client = OpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=api_key
            )
            
            response = client.chat.completions.create(
                model=config['model'],
                messages=[
                    {"role": "system", "content": "You are an expert network security analyst. Analyze network traffic and identify threats. Always respond with valid JSON only."},
                    {"role": "user", "content": self._build_comprehensive_prompt(data)}
                ],
                temperature=0.3,
                max_tokens=4096
            )
            
            return self._parse_json_response(response.choices[0].message.content)
            
        except Exception as e:
            logging.error(f"OpenRouter error: {e}")
            return None
    
    def _build_comprehensive_prompt(self, data):
        """Build comprehensive analysis prompt with all tool data"""
        
        stats = data.get('overall_statistics', {})
        suricata = data.get('suricata_alerts', [])
        tcpdump_summary = data.get('tcpdump', {}).get('summary', {})
        http = data.get('http_traffic', [])
        flows = data.get('network_flows', [])
        
        prompt = f"""You are a senior network security analyst with 30 years of experience. Analyze this comprehensive network security data from multiple monitoring tools.

**CRITICAL DATA SOURCES:**

1. **Suricata IDS Alerts** ({len(suricata)} alerts)
   - Real-time intrusion detection alerts
   - Signature-based threat detection
   - {json.dumps(suricata[:10], indent=2) if suricata else 'No alerts'}

2. **tcpdump Packet Analysis** ({tcpdump_summary.get('total_packets', 0)} packets)
   - Total bytes: {tcpdump_summary.get('total_bytes', 0)}
   - Unique sources: {tcpdump_summary.get('unique_src_ips', 0)}
   - Unique destinations: {tcpdump_summary.get('unique_dst_ips', 0)}
   - Protocols: {json.dumps(tcpdump_summary.get('protocols', {}))}

3. **HTTP Traffic** ({len(http)} requests)
   {json.dumps(http[:10], indent=2) if http else 'No HTTP traffic'}

4. **Network Flows** ({len(flows)} flows)
   {json.dumps(flows[:10], indent=2) if flows else 'No flows'}

**ANALYSIS REQUIREMENTS:**

1. **Threat Detection:**
   - Analyze Suricata alerts for critical threats
   - Correlate with packet data and flows
   - Identify: Port scans, DDoS, Malware, Botnets, Data exfiltration
   - Rate severity: CRITICAL, HIGH, MEDIUM, LOW

2. **Anomaly Detection:**
   - Traffic volume spikes
   - Unusual protocols or ports
   - Suspicious connection patterns
   - Off-hours activity

3. **URL/Domain Analysis:**
   - Extract domains from HTTP traffic
   - Identify: Phishing, DGA, C&C servers, Malware domains
   - Check for typosquatting

4. **Network Health:**
   - Overall network health score (0-100)
   - Based on: Alert severity, traffic patterns, anomalies

**RESPOND WITH ONLY VALID JSON (no markdown):**

{{
  "analysis_timestamp": "{datetime.now().isoformat()}",
  "overall_threat_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "network_health_score": 0-100,
  "suricata_analysis": {{
    "total_alerts": {len(suricata)},
    "critical_alerts": 0,
    "high_priority_threats": [],
    "alert_categories": {{}}
  }},
  "threats_detected": [
    {{
      "threat_id": "THR-{datetime.now().strftime('%Y%m%d')}-001",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "confidence": 0.0-1.0,
      "threat_type": "Port Scan|DDoS|Malware|Botnet|Data Exfiltration|IDS Alert",
      "source_ip": "x.x.x.x",
      "target_ip": "x.x.x.x",
      "description": "Detailed threat description",
      "suricata_correlation": "Related Suricata alert if any",
      "recommendation": "Specific action to take",
      "indicators": ["list of indicators"]
    }}
  ],
  "device_anomalies": [
    {{
      "device_ip": "x.x.x.x",
      "anomaly_score": 0.0-1.0,
      "anomaly_type": "Unusual Traffic Volume|Suspicious Protocol|etc",
      "description": "What is unusual"
    }}
  ],
  "url_classifications": [
    {{
      "url": "http://example.com",
      "domain": "example.com",
      "risk_score": 0.0-1.0,
      "category": "Phishing|Malware|DGA|C&C|Safe",
      "action": "BLOCK|WARN|ALLOW",
      "accessed_by": ["list of IPs"]
    }}
  ],
  "behavior_patterns": [
    {{
      "pattern_type": "Botnet Beacon|Scanning Activity|Data Exfiltration",
      "confidence": 0.0-1.0,
      "device_ip": "x.x.x.x",
      "description": "Pattern description"
    }}
  ],
  "alerts": [
    {{
      "alert_id": "ALT-{datetime.now().strftime('%Y%m%d')}-001",
      "priority": "CRITICAL|HIGH|MEDIUM|LOW",
      "title": "Short title",
      "message": "Detailed message for homeowner",
      "threat_type": "IDS Alert|Port Scan|Malware|etc",
      "source_ip": "x.x.x.x",
      "confidence": 0.0-1.0,
      "recommended_action": "Action to take",
      "suricata_related": true|false
    }}
  ],
  "statistics": {{
    "packets_analyzed": {stats.get('total_data_points', 0)},
    "threats_found": 0,
    "suricata_alerts_processed": {len(suricata)},
    "http_requests_analyzed": {len(http)},
    "flows_analyzed": {len(flows)}
  }}
}}

IMPORTANT: Return ONLY the JSON object. No markdown, no explanations.
"""
        
        return prompt
    
    def _parse_json_response(self, text):
        """Parse JSON from AI response"""
        text = text.strip()
        
        # Remove markdown code blocks
        if text.startswith('```'):
            text = re.sub(r'^```(?:json)?\s*\n', '', text)
            text = re.sub(r'\n```\s*$', '', text)
        
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse JSON: {e}")
            logging.debug(f"Response: {text[:500]}...")
            return None


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
                threats_json, anomalies_json, patterns_json, processing_time_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            ai_response.get('statistics', {}).get('processing_time_ms', 0)
        ))
        
        # Store alerts
        for alert in ai_response.get('alerts', []):
            cursor.execute("""
                INSERT INTO ai_alerts (
                    alert_id, priority, title, message, threat_type,
                    source_ip, confidence, indicators, recommended_action,
                    timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                datetime.now().isoformat()
            ))
        
        # Store URL classifications
        for url_data in ai_response.get('url_classifications', []):
            cursor.execute("""
                INSERT OR REPLACE INTO url_classifications (
                    url, domain, risk_score, category,
                    indicators, action, accessed_by, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                url_data.get('url'),
                url_data.get('domain'),
                url_data.get('risk_score'),
                url_data.get('category'),
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
                    first_detected, last_detected, severity
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                pattern.get('pattern_type'),
                pattern.get('device_ip'),
                pattern.get('confidence'),
                pattern.get('description'),
                datetime.now().isoformat(),
                datetime.now().isoformat(),
                'HIGH' if pattern.get('confidence', 0) > 0.8 else 'MEDIUM'
            ))
        
        # Store analysis history
        cursor.execute("""
            INSERT INTO ai_analysis_history (
                timestamp, packets_analyzed, threats_found,
                alerts_generated, analysis_duration_ms, success
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().isoformat(),
            ai_response.get('statistics', {}).get('packets_analyzed', 0),
            ai_response.get('statistics', {}).get('threats_found', 0),
            len(ai_response.get('alerts', [])),
            ai_response.get('statistics', {}).get('processing_time_ms', 0),
            1
        ))
        
        conn.commit()
        
        model_used = ai_response.get('ai_model_used', 'Unknown')
        logging.info(f"✓ Stored AI results from {model_used}")
        
        return True
        
    except Exception as e:
        logging.error(f"Error storing AI predictions: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()


def analyze_network():
    """Main function: Aggregate data, analyze with AI, store results"""
    
    logging.info("=" * 60)
    logging.info("NetGuard Pro - Comprehensive AI Analysis")
    logging.info("=" * 60)
    
    # Load configuration
    config = load_config()
    
    if not config:
        logging.error("Failed to load configuration")
        return False
    
    # Check if AI is enabled
    if not config.get('ai_enabled', False):
        logging.info("AI analysis is disabled in configuration")
        logging.info(f"Edit {CONFIG_PATH} and set ai_enabled: true")
        return False
    
    # Aggregate data from all tools
    logging.info("Step 1: Aggregating data from all monitoring tools...")
    aggregated_data = aggregate_all_data(config)
    
    if aggregated_data['overall_statistics']['total_data_points'] == 0:
        logging.warning("No data to analyze")
        return False
    
    # Export for AI
    export_file, data = export_for_ai(aggregated_data)
    
    # Create AI analyzer
    analyzer = MultiAIAnalyzer(config)
    
    # Analyze with AI
    logging.info("Step 2: Analyzing with AI models...")
    ai_response = analyzer.analyze_network_data(data)
    
    if not ai_response:
        logging.warning("No response from any AI service")
        return False
    
    # Store results
    logging.info("Step 3: Storing AI predictions...")
    success = store_ai_predictions(ai_response)
    
    if success:
        logging.info("=" * 60)
        logging.info("✅ Comprehensive AI Analysis Complete!")
        logging.info(f"   Model Used: {ai_response.get('ai_model_used', 'Unknown')}")
        logging.info(f"   Threat Level: {ai_response.get('overall_threat_level')}")
        logging.info(f"   Health Score: {ai_response.get('network_health_score')}/100")
        logging.info(f"   Threats: {len(ai_response.get('threats_detected', []))}")
        logging.info(f"   Alerts: {len(ai_response.get('alerts', []))}")
        logging.info(f"   Suricata Alerts Processed: {ai_response.get('statistics', {}).get('suricata_alerts_processed', 0)}")
        logging.info("=" * 60)
    
    return success


if __name__ == "__main__":
    success = analyze_network()
    
    if not success:
        logging.info("\nℹ️  Configure API keys in:")
        logging.info(f"   {CONFIG_PATH}")
        logging.info("\n   Edit the file and replace YOUR_GEMINI_KEY_HERE with your actual key")

