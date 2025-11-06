# Raspberry Pi-Based Unified Network Security Monitoring Platform
## IEEE Transactions Research Paper

This repository contains all materials for the research paper on implementing a comprehensive network security monitoring platform using Raspberry Pi 5 hardware.

## Project Structure

```
thesis/
├── paper.tex                     # Main IEEE paper (LaTeX)
├── references.bib                # Bibliography
├── README.md                     # This file
├── experiments/                  # Data collection scripts
│   ├── baseline_monitor.sh       # 14-day baseline monitoring
│   ├── iot_profiler.py          # 30-day IoT device profiling
│   ├── attack_simulator.sh      # 7-day attack simulations
│   ├── performance_benchmark.py  # 7-day performance testing
│   ├── export_statistics.py     # Generate tables from data
│   └── generate_figures.py      # Create publication figures
├── data/                        # Experimental data (generated)
│   ├── baseline/
│   ├── iot_profiling/
│   ├── attack_simulation/
│   └── performance/
├── figures/                     # Generated figures (PDF/PNG)
├── tables/                      # Generated tables (CSV/LaTeX)
└── logs/                        # Experiment logs

```

## Experimental Campaign Timeline

### Phase 1: Baseline Monitoring (Days 1-14)
- **Purpose**: Establish normal network traffic patterns
- **Script**: `experiments/baseline_monitor.sh`
- **Metrics**: CPU, memory, disk I/O, packet capture rates
- **Collection**: Every 6 hours (4 samples/day)

### Phase 2: IoT Device Profiling (Days 15-30)
- **Purpose**: Identify, classify, and security-score IoT devices
- **Script**: `experiments/iot_profiler.py`
- **Metrics**: Device types, OS, vendors, security scores, open ports
- **Collection**: Daily aggregation

### Phase 3: Attack Simulations (Days 31-37)
- **Purpose**: Test detection capabilities against known attacks
- **Script**: `experiments/attack_simulator.sh`
- **Scenarios**:
  - Day 31: Nmap port scans (SYN, UDP, OS detection)
  - Day 32: DDoS attacks (SYN flood, UDP flood, ICMP flood)
  - Day 33: Mirai botnet traffic replay
  - Day 34: IoT exploitation attempts
  - Days 35-37: Mixed attack scenarios
- **Metrics**: Detection time, true/false positives, accuracy

### Phase 4: Performance Benchmarking (Days 38-45)
- **Purpose**: Quantify system performance under various loads
- **Script**: `experiments/performance_benchmark.py`
- **Metrics**: Detailed CPU/memory/disk/network statistics
- **Collection**: Every 5 minutes (288 samples/day)
- **Load Conditions**:
  - Days 38-39: Normal load
  - Days 40-41: Medium load (simulated traffic)
  - Days 42-43: High load (stress testing)
  - Days 44-45: Validation runs

## Running the Experiments

### Prerequisites
- Raspberry Pi 5 (8GB model recommended)
- All monitoring tools installed (see main NetGuard installation)
- Python 3.9+ with required packages: `pip install -r requirements.txt`
- Network interfaces configured (eno1, wlo1, external WiFi adapter)

### Execute Complete Campaign

```bash
# Start baseline monitoring (runs for 14 days)
cd /home/jarvis/thesis/experiments
nohup bash baseline_monitor.sh &

# After 14 days, start IoT profiling (runs for 30 days)
nohup python3 iot_profiler.py &

# After IoT profiling completes, run attack simulations (7 days)
sudo bash attack_simulator.sh

# Finally, run performance benchmarks (7 days)
python3 performance_benchmark.py

# Total campaign duration: 45 days + analysis time
```

### Generate Paper Materials

```bash
# Export all tables from collected data
python3 experiments/export_statistics.py

# Generate all figures
python3 experiments/generate_figures.py

# Compile the paper (requires LaTeX)
cd /home/jarvis/thesis
pdflatex paper.tex
bibtex paper
pdflatex paper.tex
pdflatex paper.tex
```

## Key Results (Expected)

### Performance Metrics
- **Packet Capture Rate**: 5,200+ pps sustained
- **Packet Drop Rate**: <2% at normal load
- **CPU Utilization**: 15-25% average, 45% peak
- **Memory Usage**: 960MB average for all services
- **Power Consumption**: 8.2W average

### Detection Accuracy
- **Port Scans**: 98.5% detection rate, 0.1% false positive
- **DDoS Attacks**: 100% detection rate
- **Botnet Traffic**: 94.2% detection rate
- **IoT Exploits**: 92.3% detection rate

### IoT Device Classification
- **Total Devices Profiled**: 23 devices
- **Classification Accuracy**: 91%
- **Device Categories**: 8 (cameras, TVs, speakers, routers, phones, computers, smart home, other)
- **Security Score Range**: 15-89/100

### Cost-Performance Analysis
- **Pi 5 Cost**: $80 + $40 accessories = $120 total
- **Comparable Server**: $800 (10x cost)
- **Pi 5 Performance**: 65% of server capabilities
- **Cost-Performance Ratio**: 210% of server (65pps/$ vs 31pps/$)
- **Optimal Use Case**: Networks with <50 devices

## Paper Sections

1. **Introduction** (1.5 pages)
   - Background, motivation, problem statement
   - Research objectives and contributions

2. **Related Work** (2 pages)
   - Network monitoring evolution
   - Passive OS fingerprinting
   - Raspberry Pi security applications
   - IoT security challenges

3. **System Architecture** (2.5 pages)
   - Hardware selection
   - Tool integration methodology
   - Database schema design
   - Real-time processing pipeline

4. **Tool Integration Methodology** (2 pages)
   - Packet capture layer
   - Protocol analysis layer
   - Passive fingerprinting layer
   - Application layer analysis
   - Flow and bandwidth analysis

5. **IoT Security Framework** (1.5 pages)
   - Device identification algorithms
   - Vulnerability detection
   - Threat detection rules
   - Security scoring system

6. **Experimental Methodology** (1.5 pages)
   - Network environment
   - Data collection phases
   - Attack scenarios
   - Performance metrics
   - Comparative baseline

7. **Results and Analysis** (3 pages)
   - System performance results (7 tables, 7 figures)
   - Tool integration effectiveness
   - Threat detection accuracy
   - IoT device profiling results
   - Comparative performance analysis
   - Attack simulation results

8. **Discussion** (1.5 pages)
   - Key findings
   - Advantages of unified platform
   - Performance bottlenecks
   - Limitations
   - Deployment considerations

9. **Conclusion** (0.5 pages)
   - Summary of contributions
   - Future research directions

10. **References** (30-40 citations)

## Citation

If you use this work, please cite:

```bibtex
@article{your_paper_2024,
  title={A Unified Network Security Monitoring Platform on Raspberry Pi: Integration of Multiple Passive Tools for Real-Time Threat Detection and IoT Security},
  author={Your Name},
  journal={IEEE Transactions on [Target Journal]},
  year={2024}
}
```

## License

This research is conducted for academic purposes. The monitoring platform implementation is open-source. See LICENSE file for details.

## Contact

For questions about this research:
- Email: your.email@university.edu
- GitHub: [your-username]/raspberry-pi-network-monitor

## Acknowledgments

- Raspberry Pi Foundation for hardware
- Open-source community for monitoring tools
- Network administrators who provided test environments

