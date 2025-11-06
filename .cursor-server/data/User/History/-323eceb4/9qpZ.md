<!-- e911d575-41fb-4866-8847-6fa2e737adf7 4f6e9a77-6901-4183-8228-0e7773ecb0e9 -->
# NetGuard Pro - Complete Implementation Plan

## Phase 1: Foundation & Directory Structure

**Create organized directory structure:**

```
~/NetGuard/
├── captures/           # All raw capture files
│   ├── tcpdump/, suricata/{alerts,http,dns,tls,files,flow,ssh,smtp,ftp,anomaly,stats}/
│   ├── tshark/, p0f/, argus/, ngrep/, netsniff/, httpry/, iftop/, nethogs/
│   └── processed_json/
├── scripts/            # All Python processing scripts
├── web/               # Flask application
│   ├── templates/     # HTML templates
│   └── static/        # CSS/JS assets
├── configs/           # Configuration files
├── services/          # Systemd service files
├── logs/system/       # Service logs
├── network.db         # SQLite database
└── README.md          # Documentation
```

## Phase 2: Database Schema

**Create SQLite database with schemas for:**

1. **tcpdump tables** (dynamic naming: `network_YYYYMMDD_HHMMSS`)

   - Columns: id, timestamp, source_ip, source_port, destination_ip, destination_port, protocol, raw_data

2. **Suricata tables** (11 categories: `suricata_alerts_*`, `suricata_http_*`, etc.)

   - Category-specific schemas with 28+ columns for comprehensive data

3. **Analysis tool tables** (8 tools: `tshark_*`, `p0f_*`, `argus_*`, `ngrep_*`, `netsniff_*`, `httpry_*`, `iftop_*`, `nethogs_*`)

   - Tool-specific schemas with timestamps

**Script:** `scripts/init_database.py` - Creates all table schemas dynamically

## Phase 3: Core Capture System (eno1 - tcpdump)

**Files to create:**

1. `scripts/start_tcpdump.sh` - Launch tcpdump with proper flags
2. `scripts/pcap_to_json.py` - Convert PCAP to JSON using scapy/tshark
3. `scripts/json_to_sqlite.py` - Insert JSON into timestamped SQLite tables

**Configuration:**

- Interface: eno1 (192.168.1.161)
- Rotation: 10 minutes
- Buffer: 8MB (-B 8192)
- Snaplen: 65535 bytes
- Output: `~/NetGuard/captures/tcpdump/capture_YYYYMMDD_HHMMSS.pcap`

## Phase 4: Suricata IDS/IPS Configuration (eno1)

**Files to create:**

1. `configs/suricata.yaml` - Custom configuration with:

   - 11 EVE JSON outputs (alerts, http, dns, tls, files, flow, ssh, smtp, ftp, anomaly, stats)
   - 15-minute log rotation
   - Ring buffer: 8192 packets
   - Rule management (45,633+ rules)

2. `scripts/suricata_collector.py` - Process EVE logs:

   - Read 11 category log files
   - Parse JSON entries
   - Insert into categorized SQLite tables with timestamps
   - Handle log rotation gracefully

**Suricata setup:**

- Update rules: `sudo suricata-update`
- Enable all rulesets
- Configure HOME_NET to 192.168.1.0/24

## Phase 5: WiFi Analysis Tools (wlo1)

**Create 4 collector scripts for wlo1:**

1. **tshark_collector.py**

   - Launch: `tshark -i wlo1 -b filesize:100000 -b files:10 -w captures/tshark/capture.pcap`
   - Parse: Protocol breakdown, packet metadata
   - Insert: `tshark_YYYYMMDD_HHMMSS` tables

2. **p0f_collector.py**

   - Launch: `sudo p0f -i wlo1 -o captures/p0f/p0f.log -d`
   - Parse: OS fingerprints, device detection
   - Insert: `p0f_YYYYMMDD_HHMMSS` tables

3. **argus_collector.py**

   - Launch: `sudo argus -i wlo1 -B 8m -S 60 -w captures/argus/argus.out`
   - Parse: Flow data (duration, bytes, packets, TCP states)
   - Insert: `argus_YYYYMMDD_HHMMSS` tables

4. **ngrep_collector.py**

   - Launch: `sudo ngrep -d wlo1 -W byline -q -O captures/ngrep/ngrep.log`
   - Parse: Pattern matches (HTTP requests, sensitive data)
   - Insert: `ngrep_YYYYMMDD_HHMMSS` tables

## Phase 6: High-Performance Capture (wlx1cbfce6265ad)

**Create netsniff-ng collector:**

**File:** `scripts/netsniff_collector.py`

- Launch: `sudo netsniff-ng -i wlx1cbfce6265ad --in eth --out captures/netsniff/ --interval 10min --ring-size 8192 --bind-cpu 0,1 --silent`
- Parse: High-speed PCAP files
- Insert: `netsniff_YYYYMMDD_HHMMSS` tables

## Phase 7: Application Layer Tools (eno1)

**Create 3 collector scripts:**

1. **httpry_collector.py**

   - Launch: `sudo httpry -i eno1 -o captures/httpry/httpry.log -d -b`
   - Parse: URLs, HTTP methods, user agents, response codes
   - Insert: `httpry_YYYYMMDD_HHMMSS` tables

2. **iftop_collector.py**

   - Launch: `sudo iftop -i eno1 -t -s 10 -L 1000 -o 10s > captures/iftop/iftop.log`
   - Parse: Bandwidth per connection, data transfer rates
   - Insert: `iftop_YYYYMMDD_HHMMSS` tables

3. **nethogs_collector.py**

   - Launch: `sudo nethogs -t -d 5 eno1 > captures/nethogs/nethogs.log`
   - Parse: Per-process bandwidth (PID, process name, send/receive rates)
   - Insert: `nethogs_YYYYMMDD_HHMMSS` tables

## Phase 8: Master Collection Service

**File:** `scripts/analysis_tools_collector.py`

- Orchestrates all 8 analysis tool collectors
- Runs every 30 seconds
- Handles process lifecycle (start/stop/restart)
- Logs errors to `logs/system/analysis-tools.log`

## Phase 9: Flask Web Dashboard

**Create professional web interface:**

### Main Application (`web/app.py`)

- Flask routes for all pages
- SQLite query functions
- DataTables integration
- Bootstrap 5 UI

### Templates (7 HTML files):

1. **index.html** - Main dashboard

   - 3 navigation cards (tcpdump, Suricata, Analysis Tools)
   - Real-time statistics (total tables, recent captures)
   - Gradient design with professional styling

2. **tcpdump.html** - tcpdump table listing

   - Show all `network_*` tables with timestamps and record counts
   - Click to view detailed data

3. **tcpdump_table.html** - Individual table view

   - DataTables with search, sort, pagination
   - Color-coded IPs (light blue), ports (purple), protocols (gray badges)

4. **suricata.html** - Suricata categories overview

   - 11 color-coded category cards
   - Show table counts per category

5. **suricata_category.html** - Category table listing

   - Tables for specific category (e.g., all `suricata_alerts_*`)

6. **suricata_table.html** - Individual Suricata table

   - DataTables with 28+ columns
   - Event type badges (color-coded by severity)
   - Modal for raw JSON viewing

7. **analysis.html** - Analysis tools overview

   - 8 tool cards with descriptions and icons
   - Latest capture timestamps

8. **analysis_tool.html** - Individual tool data view

   - Tool-specific table display with DataTables
   - Real-time data (refreshes every 30s)

### Static Assets:

- Bootstrap 5.3 CSS/JS
- DataTables CSS/JS
- jQuery
- Custom CSS for color coding and styling

## Phase 10: Systemd Services

**Create 6 service files in `services/`:**

1. **network-capture.service**

   - Runs: `scripts/start_tcpdump.sh`
   - Continuous tcpdump capture on eno1

2. **pcap-json-converter.service**

   - Runs: `scripts/pcap_to_json.py`
   - Watches for new PCAP files, converts to JSON

3. **json-sqlite-converter.service**

   - Runs: `scripts/json_to_sqlite.py`
   - Inserts JSON data into SQLite

4. **suricata-categorized-collector.service**

   - Runs: `scripts/suricata_collector.py`
   - Processes Suricata EVE logs every 15 minutes

5. **analysis-tools-collector.service**

   - Runs: `scripts/analysis_tools_collector.py`
   - Collects data from 8 tools every 30 seconds

6. **network-dashboard.service**

   - Runs: `web/app.py`
   - Flask web server on port 8080

**All services:**

- Auto-restart on failure
- Start on boot (enabled)
- Proper dependencies
- Logging to `logs/system/`

## Phase 11: Network Interface Optimization

**Create:** `scripts/optimize_interfaces.sh`

```bash
# Disable offloading for accurate capture
sudo ethtool -K eno1 gro off lro off tso off gso off
sudo ethtool -K wlo1 gro off lro off tso off gso off
sudo ethtool -K wlx1cbfce6265ad gro off lro off tso off gso off

# Increase ring buffers
sudo ethtool -G eno1 rx 4096 tx 4096
sudo ethtool -G wlo1 rx 4096 tx 4096
sudo ethtool -G wlx1cbfce6265ad rx 4096 tx 4096

# Set performance governor
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

**Add to crontab:** `@reboot /home/jarvis/NetGuard/scripts/optimize_interfaces.sh`

## Phase 12: Documentation & Finalization

**Create:** `README.md`

- System overview
- Directory structure explanation
- Service management commands
- Troubleshooting guide
- Configuration reference

**Verification checklist:**

- [ ] All directories created
- [ ] Database initialized with schemas
- [ ] All 10 Python scripts functional
- [ ] Suricata configuration applied
- [ ] 6 systemd services created and enabled
- [ ] Flask dashboard accessible at http://192.168.1.161:8080
- [ ] Network interfaces optimized
- [ ] All capture tools running and logging data
- [ ] DataTables working (search, sort, pagination)
- [ ] No hardcoded values (use config files)

## Implementation Order

**Critical path (must be done in order):**

1. Directory structure → Database schema
2. tcpdump capture → PCAP to JSON → JSON to SQLite
3. Suricata config → Suricata collector
4. Analysis tool collectors (can be parallel)
5. Flask dashboard (depends on database)
6. Systemd services (depends on all scripts)
7. Interface optimization → Enable all services
8. Testing → Documentation

**Estimated time:** 4-6 hours for complete implementation

## Key Technical Decisions

- **Language:** Python 3 for all scripts (consistency)
- **Libraries:** scapy/dpkt (PCAP parsing), sqlite3, flask, watchdog (file monitoring)
- **Table naming:** Timestamp-based for automatic chronological organization
- **Error handling:** All scripts use try/except with logging
- **Performance:** Buffered writes, batch inserts for SQLite
- **Security:** Services run as sudo where needed (network capture requires root)

## Success Criteria

✓ Zero packet loss during capture

✓ All 10 tools collecting data continuously

✓ Database tables populating every 10-30 seconds

✓ Dashboard loads in < 2 seconds

✓ DataTables functional with 1000+ records

✓ System uptime > 24 hours without crashes

✓ CPU usage < 40% during normal operation

✓ All services auto-restart on failure

### To-dos

- [ ] Create complete directory structure in ~/NetGuard with all subdirectories for captures, scripts, web, configs, services, logs
- [ ] Initialize SQLite database with schemas for tcpdump (network_*), Suricata (11 categories), and 8 analysis tool tables
- [ ] Create tcpdump capture system: start_tcpdump.sh, pcap_to_json.py, json_to_sqlite.py for eno1 interface
- [ ] Configure Suricata with custom suricata.yaml (11 EVE outputs) and create suricata_collector.py for categorized data processing
- [ ] Create 4 WiFi analysis collectors for wlo1: tshark_collector.py, p0f_collector.py, argus_collector.py, ngrep_collector.py
- [ ] Create netsniff_collector.py for high-performance capture on wlx1cbfce6265ad interface
- [ ] Create 3 application layer collectors for eno1: httpry_collector.py, iftop_collector.py, nethogs_collector.py
- [ ] Create analysis_tools_collector.py master orchestrator that manages all 8 analysis tools with 30-second collection intervals
- [ ] Create Flask web application with app.py and 8 HTML templates (index, tcpdump, suricata, analysis views) with DataTables and Bootstrap 5 UI
- [ ] Create 6 systemd service files for network-capture, pcap-json-converter, json-sqlite-converter, suricata-collector, analysis-tools-collector, and network-dashboard
- [ ] Create optimize_interfaces.sh script to disable offloading, increase ring buffers, set performance governor for eno1, wlo1, wlx1cbfce6265ad
- [ ] Create comprehensive README.md, verify all services running, test dashboard accessibility, confirm data collection from all 10 tools