#!/bin/bash

echo "=========================================="
echo "Setting up AI Models with Complete Fallbacks"
echo "=========================================="

echo ""
echo "🤖 AI Model Configuration:"
echo "• Primary: Gemini (7 models)"
echo "  - gemini-2.5-pro"
echo "  - gemini-2.5-flash"
echo "  - gemini-2.5-flash-lite"
echo "  - gemini-2.0-flash"
echo "  - gemini-2.0-flash-lite"
echo "  - learnlm-2.0-flash-experimental"
echo "  - gemini-2.0-flash-exp"
echo ""
echo "• Fallback 1: Groq (3 models)"
echo "  - llama-3.3-70b-versatile"
echo "  - llama-3.1-70b-versatile"
echo "  - mixtral-8x7b-32768"
echo ""
echo "• Fallback 2: OpenRouter (4 models)"
echo "  - deepseek/deepseek-r1-distill-qwen-1.5b"
echo "  - qwen/qwen-coder-480b"
echo "  - deepseek/deepseek-v3.1"
echo "  - meta-llama/llama-3.1-405b-instruct"

echo ""
echo "🔄 Restarting AI Aggregator with new configuration..."

# Stop AI aggregator
sudo systemctl stop ai-5min-aggregator.timer 2>/dev/null
sudo systemctl stop ai-5min-aggregator.service 2>/dev/null

# Copy service files
sudo cp /home/jarvis/NetGuard/services/ai-5min-aggregator.service /etc/systemd/system/
sudo cp /home/jarvis/NetGuard/services/ai-5min-aggregator.timer /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable and start timer
sudo systemctl enable ai-5min-aggregator.timer
sudo systemctl start ai-5min-aggregator.timer

# Restart Flask
sudo pkill -f "python3.*app.py" 2>/dev/null || true
sleep 3

cd /home/jarvis/NetGuard/web
nohup python3 app.py > /tmp/flask.log 2>&1 &
sleep 3

echo ""
echo "🧪 Testing AI System with Multiple Models..."
python3 /home/jarvis/NetGuard/TEST_AI_AGGREGATOR.py

echo ""
echo "✅ AI Model Setup Complete!"
echo ""
echo "🎯 The system will now:"
echo "1. Try all 7 Gemini models in order"
echo "2. If Gemini fails → Try all 3 Groq models"
echo "3. If Groq fails → Try all 4 OpenRouter models"
echo "4. Store results in database"
echo "5. Update AI dashboard with real-time data"
echo ""
echo "📊 Check your AI dashboard for live analysis!"
