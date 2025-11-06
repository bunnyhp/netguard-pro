# NetGuard Pro

**NetGuard Pro** is a comprehensive, professional-grade network security monitoring system that provides complete visibility into network traffic, identifies security threats, and delivers actionable insights through an intuitive web dashboard.

## Features

- **Multi-Interface Monitoring**: Captures traffic across multiple network interfaces
- **Zero Packet Loss Architecture**: Optimized for high-performance capture
- **Real-Time Threat Detection**: Suricata IDS integration with 45,000+ rules
- **10 Specialized Tools**: Each analyzing different aspects of network traffic
  - tcpdump - Raw packet capture
  - Suricata - IDS/IPS with protocol analysis
  - tshark - Protocol dissection
  - p0f - Passive OS fingerprinting
  - argus - Network flow analysis
  - ngrep - Pattern matching
  - netsniff-ng - High-performance capture
  - httpry - HTTP traffic logging
  - iftop - Bandwidth monitoring
  - nethogs - Per-process bandwidth
- **Professional Web Dashboard**: Bootstrap 5 + DataTables for advanced visualization
- **Automated Data Processing**: Continuous capture, conversion, and storage pipeline
- **IoT Security Framework**: Device identification, vulnerability detection, and security scoring

## Quick Start

### Prerequisites

- Linux system (Ubuntu/Debian recommended)
- Python 3.8+
- Root/sudo access for packet capture
- Network monitoring tools installed:
  - tcpdump
  - suricata
  - tshark
  - p0f
  - argus
  - ngrep
  - netsniff-ng
  - httpry
  - iftop
  - nethogs

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/netguard-pro.git
   cd netguard-pro/NetGuard
   ```

2. **Install Python dependencies**
   ```bash
   pip3 install -r ../requirements.txt
   ```

3. **Configure paths** (optional)
   - Edit `config.py` to customize paths
   - Or set environment variables:
     ```bash
     export NETGUARD_DB_PATH="/path/to/network.db"
     export NETGUARD_WEB_HOST="0.0.0.0"
     export NETGUARD_WEB_PORT="8080"
     ```

4. **Initialize the database**
   ```bash
   python3 scripts/init_database.py
   ```

5. **Configure AI features** (optional)
   ```bash
   cp config/ai_config.json.template config/ai_config.json
   # Edit config/ai_config.json and add your API keys
   ```

6. **Set up systemd services**
   ```bash
   sudo cp services/*.service /etc/systemd/system/
   sudo systemctl daemon-reload
   ```

7. **Start services**
   ```bash
   sudo systemctl start network-capture.service
   sudo systemctl start network-dashboard.service
   # ... start other services as needed
   ```

8. **Access the dashboard**
   ```
   http://localhost:8080
   ```

## Configuration

### Network Interfaces

Edit `config.py` or set environment variables to configure your network interfaces:
- `NETGUARD_INTERFACE_PRIMARY` - Primary Ethernet interface
- `NETGUARD_INTERFACE_WIFI` - WiFi interface
- `NETGUARD_INTERFACE_USB_WIFI` - USB WiFi adapter

### Database

The default database location is `network.db` in the project root. Override with:
```bash
export NETGUARD_DB_PATH="/path/to/network.db"
```

### Web Dashboard

Default: `http://0.0.0.0:8080`

Configure with:
```bash
export NETGUARD_WEB_HOST="0.0.0.0"
export NETGUARD_WEB_PORT="8080"
```

## Project Structure

```
NetGuard/
├── config/              # Configuration files
│   ├── ai_config.json.template
│   ├── alert_rules.json
│   ├── iot_signatures.json
│   └── known_devices.json
├── configs/            # Suricata configuration
├── scripts/            # Python processing scripts
│   ├── init_database.py
│   ├── *_collector.py  # Data collectors
│   └── ...
├── services/           # Systemd service files
├── web/                # Flask web application
│   ├── app.py
│   └── templates/
├── captures/           # Network capture files (gitignored)
├── logs/               # System logs (gitignored)
└── README.md

```

## Documentation

- [README.md](README.md) - Complete documentation
- [QUICKSTART.md](QUICKSTART.md) - Quick start guide
- [docs/](docs/) - Additional documentation

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](../CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

## Disclaimer

This software is for educational and authorized network monitoring purposes only. Users are responsible for ensuring compliance with local laws and regulations regarding network monitoring and privacy.

## Acknowledgments

- Open-source community for monitoring tools
- Flask, Bootstrap, and DataTables for the web interface
- All contributors and users of NetGuard Pro
