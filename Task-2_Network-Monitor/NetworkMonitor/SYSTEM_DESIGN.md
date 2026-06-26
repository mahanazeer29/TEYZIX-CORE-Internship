# System Design Overview
## Network Monitoring & Log Analysis System — CPP-2

---

## Architecture

```
NetworkMonitor/
│
├── main.cpp                  ← CLI Dashboard & Menu Controller
│
├── include/
│   ├── structures.h          ← Data Structures (NetworkLog, Alert, Report, IPStats)
│   ├── log_processor.h       ← Log file loading & parsing interface
│   ├── analyzer.h            ← Analysis & threat detection interface
│   └── report_generator.h   ← Report export interface
│
├── src/
│   ├── log_processor.cpp     ← CSV parsing, validation, corrupted record handling
│   ├── analyzer.cpp          ← Statistics, threat detection, search/filter logic
│   └── report_generator.cpp ← Text + CSV report generation
│
├── logs/
│   └── network.csv           ← Sample log dataset
│
├── reports/                  ← Auto-created output folder for reports
├── Makefile
└── README.md
```

---

## Data Flow

```
Log File (CSV)
     │
     ▼
LogProcessor::loadFromFile()
  ├── parseLine()       ← Split CSV fields
  ├── validateLog()     ← Check IP, status code, timestamp
  └── ProcessingStats   ← Track valid/corrupted records
     │
     ▼
std::vector<NetworkLog>
     │
     ▼
Analyzer (constructed with logs)
  ├── buildIPCache()           ← Map<IP → IPStats>
  ├── getTotalRequests()
  ├── getUniqueIPCount()
  ├── getMostActiveIP()
  ├── getPeakHour()
  ├── getErrorFrequency()
  │
  ├── detectExcessiveRequests()  ← DDoS detection
  ├── detectBruteForce()         ← Repeated failed logins
  ├── detectTrafficSpike()       ← Hour with >3x avg traffic
  ├── detectBlockedIPAccess()    ← Blocked IP list check
  │
  ├── searchByIP()
  ├── searchByDate()
  ├── searchByEventType()
  ├── filterSuspicious()
  └── filterErrors()
     │
     ▼
std::vector<Alert>  +  Report
     │
     ▼
ReportGenerator
  ├── printReport()          ← Colour-coded CLI output
  ├── saveTextReport()       ← .txt file
  └── saveCSVReport()        ← .csv file
```

---

## Core Data Structures

### NetworkLog
| Field         | Type   | Description                        |
|---------------|--------|------------------------------------|
| id            | int    | Line number in file                |
| timestamp     | string | YYYY-MM-DD HH:MM:SS                |
| sourceIP      | string | Source IP address                  |
| destinationIP | string | Destination IP address             |
| eventType     | string | LOGIN / REQUEST / ERROR / BLOCKED  |
| statusCode    | int    | HTTP status code (100–599)         |
| message       | string | Log message                        |
| valid         | bool   | False if record is corrupted       |

### Alert
| Field       | Type   | Description                          |
|-------------|--------|--------------------------------------|
| alertID     | int    | Unique alert ID                      |
| alertType   | string | BRUTE_FORCE / DDOS_SUSPECTED / etc.  |
| severity    | string | LOW / MEDIUM / HIGH / CRITICAL       |
| sourceIP    | string | IP that triggered alert              |
| description | string | Human-readable description           |
| timestamp   | string | When detected                        |

### IPStats
| Field         | Type   | Description                   |
|---------------|--------|-------------------------------|
| ip            | string | IP address                    |
| totalRequests | int    | Total request count           |
| failedLogins  | int    | Count of 403 LOGIN events     |
| errorCount    | int    | Count of 4xx/5xx responses    |
| isBlocked     | bool   | Has BLOCKED event             |

---

## Threat Detection Rules

| Rule                   | Trigger Condition              | Severity        |
|------------------------|-------------------------------|-----------------|
| Excessive Requests     | >100 requests from one IP     | HIGH / CRITICAL |
| Brute Force            | ≥5 failed LOGINs from one IP  | HIGH / CRITICAL |
| Traffic Spike          | Hour with >3× hourly average  | MEDIUM          |
| Blocked IP Access      | Request from blocked IP list  | CRITICAL        |

---

## Performance Considerations

- IP statistics are cached in `std::map<string, IPStats>` built once in constructor.
- All search/filter operations are O(n) single-pass.
- File reading is line-by-line (no full-file loading into memory at once).
- Large datasets supported — only valid records are stored.
