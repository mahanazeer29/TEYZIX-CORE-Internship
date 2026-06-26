#pragma once
#include <string>
#include <vector>
#include <ctime>

// ============================================================
//  DATA STRUCTURES
// ============================================================

struct NetworkLog {
    int         id;
    std::string timestamp;
    std::string sourceIP;
    std::string destinationIP;
    std::string eventType;   // LOGIN, REQUEST, ERROR, BLOCKED, TRANSFER
    int         statusCode;  // 200, 403, 404, 500, etc.
    std::string message;
    bool        valid;       // false if record was corrupted
};

struct Alert {
    int         alertID;
    std::string alertType;    // BRUTE_FORCE, DDOS, BLOCKED_IP, SPIKE
    std::string severity;     // LOW, MEDIUM, HIGH, CRITICAL
    std::string description;
    std::string timestamp;
    std::string sourceIP;
};

struct IPStats {
    std::string ip;
    int         totalRequests;
    int         failedLogins;
    int         errorCount;
    bool        isBlocked;
};

struct Report {
    std::string generatedDate;
    int         totalLogs;
    int         validLogs;
    int         corruptedLogs;
    int         uniqueIPs;
    int         totalAlerts;
    int         criticalAlerts;
    std::string topActiveIP;
    std::string peakHour;
    std::vector<std::string> securityFindings;
    std::vector<std::string> recommendations;
};

struct ProcessingStats {
    int totalRead       = 0;
    int validParsed     = 0;
    int corruptedSkipped= 0;
    int alertsGenerated = 0;
};
