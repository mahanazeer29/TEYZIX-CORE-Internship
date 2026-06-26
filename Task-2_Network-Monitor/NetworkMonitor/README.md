# Network Monitoring & Log Analysis System
### Teyzix Core Internship — Task CPP-2 | June 2026

---

## Overview

A command-line C++17 application that processes network activity logs (CSV), detects security threats, generates statistics, and exports monitoring reports.

---

## Features

| Category         | Features                                                                 |
|------------------|--------------------------------------------------------------------------|
| Log Processing   | CSV import, large file support, corrupted record handling, parse stats   |
| Activity Analysis| Total requests, unique IPs, most active IP, error frequency, peak hour  |
| Threat Detection | DDoS detection, brute-force login detection, traffic spikes, blocked IPs|
| CLI Dashboard    | Colour-coded interactive menu                                            |
| Search & Filter  | By IP, date, event type, suspicious activity, errors                    |
| Reports          | Text report (.txt) and CSV report (.csv) export                         |

---

## Project Structure

```
NetworkMonitor/
├── main.cpp
├── include/
│   ├── structures.h
│   ├── log_processor.h
│   ├── analyzer.h
│   └── report_generator.h
├── src/
│   ├── log_processor.cpp
│   ├── analyzer.cpp
│   └── report_generator.cpp
├── logs/
│   └── network.csv          ← Sample dataset
├── reports/                 ← Generated reports saved here
├── Makefile
├── SYSTEM_DESIGN.md
└── README.md
```

---

## Requirements

- **Compiler:** g++ with C++17 support
- **OS:** Windows (MSYS2/MinGW) or Linux/macOS
- **No external libraries** — uses STL only

---

## Build Instructions

### On Windows (MSYS2 / MinGW)

```bash
# Open MSYS2 terminal, navigate to project folder
cd NetworkMonitor

# Build
mingw32-make

# OR manually:
g++ -std=c++17 -Wall -O2 -o NetworkMonitor.exe main.cpp src/log_processor.cpp src/analyzer.cpp src/report_generator.cpp
```

### On Linux / macOS

```bash
cd NetworkMonitor
make

# OR manually:
g++ -std=c++17 -Wall -O2 -o NetworkMonitor main.cpp src/log_processor.cpp src/analyzer.cpp src/report_generator.cpp
```

---

## Run

```bash
# Windows
./NetworkMonitor.exe

# Linux/macOS
./NetworkMonitor
```

Make sure the `logs/` and `reports/` folders exist before running. The program will prompt you to load a log file.

---

## Usage Guide

```
MAIN MENU
------------------------------------------------------------
  [1]  Load Log File
  [2]  View Activity Statistics
  [3]  Run Threat Detection
  [4]  Search / Filter Logs
  [5]  Generate & Export Report
  [6]  View All Logs
  [7]  View Alerts
  [0]  Exit
```

**Recommended workflow:**
1. Press `1` → Enter `logs/network.csv` (or your own log file)
2. Press `2` → View statistics
3. Press `3` → Run threat detection
4. Press `4` → Search/filter
5. Press `5` → Generate and save report

---

## Log File Format (CSV)

```
timestamp,sourceIP,destinationIP,eventType,statusCode,message
2026-06-20 08:01:12,192.168.1.10,10.0.0.1,LOGIN,200,Successful login
```

**Event Types:** `LOGIN`, `REQUEST`, `ERROR`, `BLOCKED`, `TRANSFER`

**Status Codes:** Standard HTTP codes (200, 403, 404, 500, 503, etc.)

---

## Threat Detection Rules

| Alert Type        | Condition                          | Severity        |
|-------------------|------------------------------------|-----------------|
| DDOS_SUSPECTED    | >100 requests from one IP          | HIGH / CRITICAL |
| BRUTE_FORCE       | ≥5 failed LOGINs from one IP       | HIGH / CRITICAL |
| TRAFFIC_SPIKE     | Hour with >3× average traffic      | MEDIUM          |
| BLOCKED_IP_ACCESS | Request from preconfigured blocked IPs | CRITICAL    |

---

## Report Output

Reports are saved in the `reports/` folder:
- `monitoring_report.txt` — Human-readable text report
- `monitoring_report.csv` — Spreadsheet-compatible CSV

---

## Author

**Maha Nazeer**
C/C++ Developer Intern — Teyzix Core (June Batch 2026)
GitHub: [github.com/mahanazeer29](https://github.com/mahanazeer29)
