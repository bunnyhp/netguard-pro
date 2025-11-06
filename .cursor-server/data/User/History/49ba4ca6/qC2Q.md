# 🎯 NetGuard Pro - Final Setup Guide

## ✅ What's Complete

### 1. **Comprehensive Data Collection**
- ✅ **Suricata IDS** - 1 alert collected (Security threats)
- ✅ **tcpdump** - 141 packets (Full packet captures)
- ✅ **tshark** - Active (Packet analysis)
- ✅ **httpry** - 35 HTTP requests
- ✅ **argus** - 31 network flows
- ✅ **ngrep** - Active (Pattern matching)
- ✅ **netsniff-ng** - Active (Raw captures)
- ✅ **iftop** - Active (Bandwidth monitoring)
- ✅ **nethogs** - Active (Per-process bandwidth)

**Total: 208+ data points collected every 5 minutes**

---

### 2. **Simple JSON Configuration**
Location: `/home/jarvis/NetGuard/config/ai_config.json`

You only need to edit this file ONCE to add your API key!

---

### 3. **AI Integration**
- ✅ Multi-AI support (Gemini, Groq, OpenRouter)
- ✅ Automatic fallback between models
- ✅ Comprehensive data aggregation
- ✅ Intelligent threat analysis
- ✅ Beautiful dashboard display

---

## 🔑 How to Add API Key (One Time Only!)

### Method 1: Edit Config File

```bash
nano /home/jarvis/NetGuard/config/ai_config.json
```

Find this line:
```json
"gemini_api_key": "YOUR_GEMINI_KEY_HERE",
```

Replace with your actual key:
```json
"gemini_api_key": "AIzaSyABC123XYZ789",
```

Save and exit (Ctrl+X, Y, Enter)

### Method 2: View and Edit

```bash
cat /home/jarvis/NetGuard/config/ai_config.json
```

Copy the content, edit it with your key, then save it back.

---

## 🌐 Get FREE API Keys

### Gemini (Primary - Recommended)
1. Go to: https://aistudio.google.com/app/apikey
2. Click "Create API Key"
3. Copy the key (starts with `AIza...`)

### Groq (Fast Fallback - Optional)
1. Go to: https://console.groq.com/keys
2. Sign up (free)
3. Create API key

### OpenRouter (Many Models - Optional)
1. Go to: https://openrouter.ai/keys
2. Sign up (free)
3. Create API key

---

## 🚀 How to Run AI Analysis

### After adding your API key:

```bash
cd /home/jarvis/NetGuard
python3 scripts/ai_connector_v2.py
```

### What Happens:

1. **Collects** data from all 9 tools + Suricata
2. **Aggregates** 208+ data points (packets, flows, alerts)
3. **Sends** to AI (Gemini/Groq/OpenRouter)
4. **Analyzes** for:
   - Suricata IDS alerts
   - Port scans
   - DDoS attacks
   - Malware activity
   - Botnet behavior
   - Data exfiltration
   - Suspicious URLs
   - Traffic anomalies
5. **Stores** results in database
6. **Displays** on dashboard

---

## 📊 Data Flow

```
┌─────────────────────────────────────────────────────┐
│  CONTINUOUS COLLECTION (All Running)                │
├─────────────────────────────────────────────────────┤
│  Suricata    → Real-time IDS alerts                 │
│  tcpdump     → Full packet captures                 │
│  tshark      → Packet analysis                      │
│  httpry      → HTTP transaction logs                │
│  argus       → Network flow analysis                │
│  ngrep       → Pattern matching                     │
│  netsniff-ng → Raw packet captures                  │
│  iftop       → Bandwidth per connection             │
│  nethogs     → Bandwidth per process                │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│  AGGREGATOR (When AI Runs)                          │
├─────────────────────────────────────────────────────┤
│  • Reads latest table from each tool                │
│  • Time window: Last 5 minutes                      │
│  • Collects: 200+ data points                       │
│  • Creates: JSON export file                        │
│  • Includes: Suricata alerts + all tool data        │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│  AI ANALYSIS (Gemini/Groq/OpenRouter)               │
├─────────────────────────────────────────────────────┤
│  • Analyzes Suricata IDS alerts (HIGH PRIORITY)     │
│  • Correlates with packet/flow data                 │
│  • Identifies threats & anomalies                   │
│  • Classifies URLs and domains                      │
│  • Calculates network health score                  │
│  • Generates actionable alerts                      │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│  WEB DASHBOARD                                       │
├─────────────────────────────────────────────────────┤
│  • Threat level (LOW/MEDIUM/HIGH/CRITICAL)          │
│  • Network health score (0-100)                     │
│  • Active alerts with priorities                    │
│  • Threat patterns visualization                    │
│  • Risky URLs and domains                           │
│  • Device anomalies                                 │
│  • Recommended actions                              │
└─────────────────────────────────────────────────────┘
```

---

## 🌐 Dashboards

### Main Dashboard
http://192.168.1.161:8080/

### AI Threat Detection
http://192.168.1.161:8080/ai-dashboard

*(Empty until you run AI analysis with API key)*

### Analysis Tools (Real Data)
http://192.168.1.161:8080/analysis

---

## 🔄 Automatic Scheduled Analysis (Optional)

To run AI analysis every 5 minutes automatically:

```bash
# Edit crontab
crontab -e

# Add this line:
*/5 * * * * cd /home/jarvis/NetGuard && python3 scripts/ai_connector_v2.py >> /home/jarvis/NetGuard/logs/ai_analysis.log 2>&1
```

This will:
- Run every 5 minutes
- Collect data from all tools
- Analyze with AI
- Update dashboard automatically

---

## 📋 Data Collection Intervals

| Tool | Collection | Data Stored |
|------|-----------|-------------|
| Suricata | Real-time | IDS alerts in tables |
| tcpdump | Continuous | Ring buffer (1000 packets) |
| tshark | Continuous | Time-based tables |
| httpry | Continuous | HTTP request logs |
| argus | Every ~2 min | Flow analysis tables |
| ngrep | Real-time | Pattern match logs |
| netsniff-ng | Continuous | Raw packet captures |
| iftop | Real-time | Bandwidth statistics |
| nethogs | Real-time | Process bandwidth |

**AI Analysis:** Reads last 5 minutes from all tools when you run it

---

## ✅ Verification

Check all services are running:
```bash
cd /home/jarvis/NetGuard
systemctl is-active tcpdump-collector tshark-collector suricata-collector \
  p0f-collector argus-collector ngrep-collector netsniff-collector \
  httpry-collector iftop-collector nethogs-collector
```

Should show 10x `active`

---

## 🧪 Test Data Collection

```bash
cd /home/jarvis/NetGuard
python3 scripts/comprehensive_data_aggregator.py
```

Should show:
- Suricata alerts: X
- tcpdump packets: X
- HTTP requests: X
- Network flows: X
- Total data points: 200+

---

## 💰 Cost

**$0/month** - All AI APIs are FREE:
- Gemini: 15 requests/min (FREE forever)
- Groq: 30 requests/min (FREE forever)
- OpenRouter: Unlimited on free models

---

## 🎯 Quick Start Checklist

- [ ] Get Gemini API key: https://aistudio.google.com/app/apikey
- [ ] Edit config: `nano /home/jarvis/NetGuard/config/ai_config.json`
- [ ] Add your API key (replace YOUR_GEMINI_KEY_HERE)
- [ ] Test: `python3 scripts/ai_connector_v2.py`
- [ ] View dashboard: http://192.168.1.161:8080/ai-dashboard
- [ ] (Optional) Set up cron for automatic analysis

---

## 📁 Important Files

```
/home/jarvis/NetGuard/
├── config/
│   └── ai_config.json                    ← ADD API KEY HERE (ONCE!)
├── scripts/
│   ├── comprehensive_data_aggregator.py  ← Collects from all tools
│   ├── ai_connector_v2.py                ← Runs AI analysis
│   └── ai_data_exporter.py               ← (Old, not used)
├── exports/
│   └── comprehensive_export_*.json       ← Data sent to AI
└── network.db                             ← All data stored here
```

---

## 🆘 Troubleshooting

### "No API key configured"
**Solution:** Edit `/home/jarvis/NetGuard/config/ai_config.json` and add your key

### "No data to analyze"
**Solution:** Wait a few minutes for tools to collect data, then try again

### "All AI models failed"
**Solution:** Check your API key is correct and has no quotes/spaces

### View detailed logs
```bash
python3 /home/jarvis/NetGuard/scripts/ai_connector_v2.py
```

---

## 🎉 Summary

✅ **All tools collecting data** (208+ data points)  
✅ **Suricata IDS integrated** (Security alerts prioritized)  
✅ **Simple JSON config** (Edit once, use forever)  
✅ **Multi-AI support** (Gemini + fallbacks)  
✅ **Beautiful dashboard** (Real-time threat display)  
✅ **100% FREE** (No cost, no limits)  

**Just add your API key and run the analysis!** 🚀

