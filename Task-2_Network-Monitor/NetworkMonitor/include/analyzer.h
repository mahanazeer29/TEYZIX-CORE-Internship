#pragma once
#include "structures.h"
#include <string>
#include <vector>
#include <map>

class Analyzer {
public:
    explicit Analyzer(const std::vector<NetworkLog>& logs);

    // ---- Core Statistics ----
    int  getTotalRequests()   const;
    int  getUniqueIPCount()   const;
    std::vector<IPStats> getIPStats() const;
    IPStats getMostActiveIP() const;
    std::map<std::string,int> getRequestFrequency() const;  // per IP
    std::map<int,int>         getErrorFrequency()   const;  // status-code counts
    std::string               getPeakHour()         const;  // "HH" string

    // ---- Threat Detection ----
    // Excessive requests from single IP (threshold configurable)
    std::vector<Alert> detectExcessiveRequests(int threshold = 100) const;
    // Repeated failed logins (403 on LOGIN events)
    std::vector<Alert> detectBruteForce(int threshold = 5)  const;
    // Traffic spike: hour with >3x average
    std::vector<Alert> detectTrafficSpike() const;
    // Any log event from a blocked IP list
    std::vector<Alert> detectBlockedIPAccess(const std::vector<std::string>& blockedIPs) const;

    // Run all detections and merge results
    std::vector<Alert> runAllDetections(const std::vector<std::string>& blockedIPs = {}) const;

    // ---- Searching / Filtering ----
    std::vector<NetworkLog> searchByIP(const std::string& ip)     const;
    std::vector<NetworkLog> searchByDate(const std::string& date)  const; // "YYYY-MM-DD"
    std::vector<NetworkLog> searchByEventType(const std::string& type) const;
    std::vector<NetworkLog> filterSuspicious(int requestThreshold = 100) const;
    std::vector<NetworkLog> filterErrors()  const;  // status >= 400

    // ---- Report Building ----
    Report buildReport(const std::vector<Alert>& alerts) const;

private:
    const std::vector<NetworkLog>& m_logs;
    mutable std::map<std::string,IPStats> m_ipCache;
    void buildIPCache() const;
};
