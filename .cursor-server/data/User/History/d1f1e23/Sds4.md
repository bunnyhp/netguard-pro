# Quick Start Guide

## Getting Started with Your IEEE Research Paper

This guide will help you begin the 45-day experimental campaign and complete your research paper.

## ✅ What's Already Done

You have a complete research infrastructure ready:
- 4 experimental scripts (baseline, IoT profiling, attacks, performance)
- 2 analysis scripts (statistics export, figure generation)
- Paper template with 3.5 pages written (Introduction, Related Work, partial Architecture)
- 37 academic references ready
- All necessary documentation

## 🚀 Start Your Experiments NOW

### Option 1: Run Complete 45-Day Campaign

```bash
cd /home/jarvis/thesis

# Day 1-14: Baseline Monitoring
nohup bash experiments/baseline_monitor.sh > logs/baseline.out 2>&1 &

# After 14 days complete, start IoT profiling (Day 15-30)
nohup python3 experiments/iot_profiler.py > logs/iot_profiler.out 2>&1 &

# After Day 30, run attack simulations (Day 31-37)
sudo bash experiments/attack_simulator.sh

# After Day 37, run performance benchmarks (Day 38-45)
python3 experiments/performance_benchmark.py
```

### Option 2: Quick Test Run (For Verification)

Test scripts with shortened durations to verify everything works:

```bash
# Edit scripts to use shorter durations (e.g., 1 hour instead of 14 days)
# Then run:
bash experiments/baseline_monitor.sh
python3 experiments/iot_profiler.py
```

## 📊 Monitor Progress

While experiments run, check progress anytime:

```bash
# View baseline monitoring logs
tail -f /home/jarvis/thesis/logs/baseline_monitor.log

# View IoT profiling logs
tail -f /home/jarvis/thesis/logs/iot_profiler.log

# View attack simulation logs
tail -f /home/jarvis/thesis/logs/attack_simulator.log

# View performance benchmark logs
tail -f /home/jarvis/thesis/logs/performance_benchmark.log

# Check data collection
ls -lh /home/jarvis/thesis/data/*/
```

## 📝 Continue Writing (During Experiments)

You can write the remaining paper sections while experiments run:

### Sections to Complete

1. **Finish Section 4: System Architecture** (1.5 pages left)
   - Database schema design
   - Real-time processing pipeline
   - Web dashboard architecture

2. **Write Section 5: Tool Integration** (2 pages)
   - Packet capture layer details
   - Protocol analysis configuration
   - Passive fingerprinting setup
   - Application layer tools

3. **Write Section 6: IoT Security Framework** (1.5 pages)
   - Device identification algorithms
   - Vulnerability detection methods
   - Security scoring system

4. **Write Section 7: Experimental Methodology** (1.5 pages)
   - Network environment description
   - Data collection phases
   - Attack scenarios
   - Metrics definitions

Edit the paper:
```bash
cd /home/jarvis/thesis
nano paper.tex
# or use your preferred editor
```

## 📈 After Experiments Complete

### Step 1: Generate Tables and Figures

```bash
cd /home/jarvis/thesis

# Generate all 7 tables from your data
python3 experiments/export_statistics.py

# Generate all 7-8 figures
python3 experiments/generate_figures.py

# Check outputs
ls -lh tables/*.csv
ls -lh figures/*.pdf
ls -lh figures/*.png
```

### Step 2: Write Results Section

With your tables and figures ready, write Section 8 (Results and Analysis):
- Include all generated tables
- Reference all figures
- Analyze performance metrics
- Compare with baselines
- Statistical significance

### Step 3: Complete Remaining Sections

- Section 9: Discussion (interpret findings, limitations)
- Section 10: Conclusion (summary, future work)
- Abstract: Write last (200-250 words summarizing everything)

### Step 4: Compile Paper

```bash
cd /home/jarvis/thesis

# Install LaTeX if needed
sudo apt-get install texlive-full

# Compile paper (runs 3 passes + bibtex)
bash compile_paper.sh

# View PDF
xdg-open paper.pdf
```

## 📋 Paper Completion Checklist

- [ ] All 10 sections written
- [ ] All 7 tables included
- [ ] All 7-8 figures included
- [ ] All 37+ references cited in text
- [ ] Abstract written (last)
- [ ] Keywords selected
- [ ] IEEE formatting verified
- [ ] Grammar and spell-checked
- [ ] Technical accuracy reviewed
- [ ] Compiled PDF generated
- [ ] Page count 12-15 pages

## 🎯 Paper Quality Checks

Before submission, verify:

```bash
# Check paper compiles without errors
bash compile_paper.sh

# Count pages
pdfinfo paper.pdf | grep Pages

# Check file size (should be <10MB)
du -h paper.pdf

# Verify all figures are high resolution
ls -lh figures/*.pdf

# Check all tables are present
ls tables/*.csv
```

## 💡 Tips for Success

### During Experiments
1. **Monitor daily**: Check logs to ensure scripts are running
2. **Backup data**: Copy `/home/jarvis/thesis/data/` regularly
3. **Document issues**: Note any anomalies in a lab notebook
4. **Generate traffic**: Browse, stream, use IoT devices to create diverse traffic
5. **Take screenshots**: Capture your dashboard for paper figures

### During Writing
1. **Write daily**: Even 30 minutes adds up
2. **Cite as you write**: Add [1], [2] references immediately
3. **Create figures early**: Easier to write around visuals
4. **Get feedback**: Share drafts with advisor/colleagues
5. **Track word count**: Aim for ~6,000-7,500 words total

### Data Analysis
1. **Verify data quality**: Check for missing values, outliers
2. **Calculate statistics**: Mean, std dev, confidence intervals
3. **Compare baselines**: Show improvements clearly
4. **Visualize first**: Graphs reveal patterns
5. **Keep raw data**: You may need to regenerate figures

## 📞 Troubleshooting

### Experiments Not Running?
```bash
# Check if services are active
systemctl status *-collector.service

# Check database is accessible
sqlite3 /home/jarvis/NetGuard/network.db ".tables"

# Check disk space
df -h /home/jarvis

# Check memory
free -h
```

### Paper Won't Compile?
```bash
# Check LaTeX installation
pdflatex --version

# Look for errors in log
cat paper.log | grep Error

# Install missing packages
sudo apt-get install texlive-latex-extra
```

### Figures Not Generating?
```bash
# Install Python packages
pip3 install -r requirements.txt

# Check matplotlib backend
python3 -c "import matplotlib; print(matplotlib.get_backend())"

# Run with verbose output
python3 experiments/generate_figures.py 2>&1 | tee figure_gen.log
```

## 🎓 Target Submission

**Recommended Journal**: IEEE Internet of Things Journal
- **Impact Factor**: 10.6 (High)
- **Acceptance Rate**: ~30%
- **Review Time**: 3-5 months
- **Open Access Option**: Yes (fee-based)

**Submission Checklist**:
1. Paper PDF (12-15 pages)
2. All figures as separate high-res files
3. Copyright form
4. Cover letter highlighting contributions
5. Suggested reviewers (3-5 experts)

## 📅 Timeline Summary

| Week | Task | Hours |
|------|------|-------|
| 1-2 | Complete Sections 4-7 | 20 |
| 3-8 | Experiments running | 2/week monitoring |
| 9 | Data analysis | 20 |
| 10 | Write Results (Section 8) | 25 |
| 11 | Write Discussion & Conclusion | 15 |
| 12 | Review, revise, format | 20 |
| **Total** | **~12 weeks** | **~120 hours** |

## ✨ You're Ready!

Everything is set up. Your next action:

```bash
cd /home/jarvis/thesis
nohup bash experiments/baseline_monitor.sh > logs/baseline.out 2>&1 &
```

Then watch the logs and continue writing!

Good luck with your research! 🚀

