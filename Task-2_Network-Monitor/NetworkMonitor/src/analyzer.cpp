#include "../include/analyzer.h"
#include <algorithm>
#include <sstream>
#include <iostream>
#include <ctime>
#include <set>

Analyzer::Analyzer(const std::vector<NetworkLog>& logs) : m_logs(logs) {
    buildIPCache();
}

void Analyzer::buildIPCache() const {
    m_ipCache.clear();
    for (const auto& log : m_logs) {
        auto& s = m_ipCache[log.sourceIP];
        s.ip = log.sourceIP;
        s.totalRequests++;
        if (log.statusCode == 403 && log.eventType == "LOGIN") s.failedLogins++;
        if (log.statusCode >= 400) s.errorCount++;
        if (log.eventType == "BLOCKED") s.isBlocked = true;
    }
}

int Analyzer::getTotalRequests() const { return (int)m_logs.size(); }

int Analyzer::getUniqueIPCount() const { return (int)m_ipCache.size(); }

std::vector<IPStats> Analyzer::getIPStats() const {
    std::vector<IPStats> result;
    for (const auto& kv : m_ipCache) result.push_back(kv.second);
    std::sort(result.begin(), result.end(),
              [](const IPStats& a, const IPStats& b){ return a.totalRequests > b.totalRequests; });
    return result;
}

IPStats Analyzer::getMostActiveIP() const {
    auto all = getIPStats();
    if (all.empty()) return {};
    return all[0];
}

std::map<std::string,int> Analyzer::getRequestFrequency() const {
    std::map<std::string,int> freq;
    for (const auto& kv : m_ipCache) freq[kv.first] = kv.second.totalRequests;
    return freq;
}

std::map<int,int> Analyzer::getErrorFrequency() const {
    std::map<int,int> freq;
    for (const auto& log : m_logs)
        if (log.statusCode >= 400) freq[log.statusCode]++;
    return freq;
}

std::string Analyzer::getPeakHour() const {
    std::map<std::string,int> hourCount;
    for (const auto& log : m_logs) {
        if (log.timestamp.size() >= 13) {
            std::string hour = log.timestamp.substr(11, 2); // "HH"
            hourCount[hour]++;
        }
    }
    std::string peak = "N/A";
    int maxC = 0;
    for (const auto& kv : hourCount)
        if (kv.second > maxC) { maxC = kv.second; peak = kv.first + ":00"; }
    return peak;
}

// ---- Threat Detection ----

std::vector<Alert> Analyzer::detectExcessiveRequests(int threshold) const {
    std::vector<Alert> alerts;
    int id = 1000;
    for (const auto& kv : m_ipCache) {
        if (kv.second.totalRequests >= threshold) {
            Alert a;
            a.alertID     = id++;
            a.alertType   = "DDOS_SUSPECTED";
            a.severity    = (kv.second.totalRequests >= threshold * 3) ? "CRITICAL" : "HIGH";
            a.sourceIP    = kv.first;
            a.description = "IP " + kv.first + " sent " +
                            std::to_string(kv.second.totalRequests) + " requests (threshold=" +
                            std::to_string(threshold) + ")";
            a.timestamp   = m_logs.empty() ? "N/A" : m_logs.back().timestamp;
            alerts.push_back(a);
        }
    }
    return alerts;
}

std::vector<Alert> Analyzer::detectBruteForce(int threshold) const {
    std::vector<Alert> alerts;
    int id = 2000;
    for (const auto& kv : m_ipCache) {
        if (kv.second.failedLogins >= threshold) {
            Alert a;
            a.alertID     = id++;
            a.alertType   = "BRUTE_FORCE";
            a.severity    = (kv.second.failedLogins >= threshold * 3) ? "CRITICAL" : "HIGH";
            a.sourceIP    = kv.first;
            a.description = "IP " + kv.first + " had " +
                            std::to_string(kv.second.failedLogins) + " failed login attempts";
            a.timestamp   = m_logs.empty() ? "N/A" : m_logs.back().timestamp;
            alerts.push_back(a);
        }
    }
    return alerts;
}

std::vector<Alert> Analyzer::detectTrafficSpike() const {
    std::map<std::string,int> hourCount;
    for (const auto& log : m_logs) {
        if (log.timestamp.size() >= 13)
            hourCount[log.timestamp.substr(11, 2)]++;
    }
    if (hourCount.empty()) return {};

    double total = 0;
    for (const auto& kv : hourCount) total += kv.second;
    double avg = total / hourCount.size();

    std::vector<Alert> alerts;
    int id = 3000;
    for (const auto& kv : hourCount) {
        if (kv.second > avg * 3.0) {
            Alert a;
            a.alertID     = id++;
            a.alertType   = "TRAFFIC_SPIKE";
            a.severity    = "MEDIUM";
            a.sourceIP    = "N/A";
            a.description = "Hour " + kv.first + ":00 had " +
                            std::to_string(kv.second) + " requests (avg=" +
                            std::to_string((int)avg) + ")";
            a.timestamp   = kv.first + ":00";
            alerts.push_back(a);
        }
    }
    return alerts;
}

std::vector<Alert> Analyzer::detectBlockedIPAccess(const std::vector<std::string>& blockedIPs) const {
    std::set<std::string> blocked(blockedIPs.begin(), blockedIPs.end());
    std::set<std::string> found;
    std::vector<Alert> alerts;
    int id = 4000;

    for (const auto& log : m_logs) {
        if (blocked.count(log.sourceIP) && !found.count(log.sourceIP)) {
            found.insert(log.sourceIP);
            Alert a;
            a.alertID     = id++;
            a.alertType   = "BLOCKED_IP_ACCESS";
            a.severity    = "CRITICAL";
            a.sourceIP    = log.sourceIP;
            a.description = "Blocked IP " + log.sourceIP + " attempted access";
            a.timestamp   = log.timestamp;
            alerts.push_back(a);
        }
    }
    return alerts;
}

std::vector<Alert> Analyzer::runAllDetections(const std::vector<std::string>& blockedIPs) const {
    std::vector<Alert> all;
    auto a1 = detectExcessiveRequests(100);
    auto a2 = detectBruteForce(5);
    auto a3 = detectTrafficSpike();
    auto a4 = detectBlockedIPAccess(blockedIPs);
    all.insert(all.end(), a1.begin(), a1.end());
    all.insert(all.end(), a2.begin(), a2.end());
    all.insert(all.end(), a3.begin(), a3.end());
    all.insert(all.end(), a4.begin(), a4.end());
    return all;
}

// ---- Search & Filter ----

std::vector<NetworkLog> Analyzer::searchByIP(const std::string& ip) const {
    std::vector<NetworkLog> res;
    for (const auto& log : m_logs) if (log.sourceIP == ip) res.push_back(log);
    return res;
}

std::vector<NetworkLog> Analyzer::searchByDate(const std::string& date) const {
    std::vector<NetworkLog> res;
    for (const auto& log : m_logs)
        if (log.timestamp.substr(0, 10) == date) res.push_back(log);
    return res;
}

std::vector<NetworkLog> Analyzer::searchByEventType(const std::string& type) const {
    std::vector<NetworkLog> res;
    for (const auto& log : m_logs) if (log.eventType == type) res.push_back(log);
    return res;
}

std::vector<NetworkLog> Analyzer::filterSuspicious(int threshold) const {
    auto freq = getRequestFrequency();
    std::set<std::string> suspicious;
    for (const auto& kv : freq) if (kv.second >= threshold) suspicious.insert(kv.first);

    std::vector<NetworkLog> res;
    for (const auto& log : m_logs)
        if (suspicious.count(log.sourceIP)) res.push_back(log);
    return res;
}

std::vector<NetworkLog> Analyzer::filterErrors() const {
    std::vector<NetworkLog> res;
    for (const auto& log : m_logs) if (log.statusCode >= 400) res.push_back(log);
    return res;
}

// ---- Report Building ----

Report Analyzer::buildReport(const std::vector<Alert>& alerts) const {
    Report r;

    // Current date
    time_t now = time(nullptr);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    r.generatedDate = buf;

    r.totalLogs      = getTotalRequests();
    r.validLogs      = r.totalLogs;
    r.corruptedLogs  = 0; // will be set by main
    r.uniqueIPs      = getUniqueIPCount();
    r.totalAlerts    = (int)alerts.size();
    r.peakHour       = getPeakHour();

    auto topIP = getMostActiveIP();
    r.topActiveIP = topIP.ip.empty() ? "N/A" : topIP.ip + " (" +
                    std::to_string(topIP.totalRequests) + " reqs)";

    r.criticalAlerts = 0;
    for (const auto& a : alerts) if (a.severity == "CRITICAL") r.criticalAlerts++;

    // Security findings
    if (r.criticalAlerts > 0)
        r.securityFindings.push_back(std::to_string(r.criticalAlerts) + " CRITICAL alerts detected.");
    auto bf = detectBruteForce(5);
    if (!bf.empty())
        r.securityFindings.push_back("Brute force attempts from " + std::to_string(bf.size()) + " IP(s).");
    auto ddos = detectExcessiveRequests(100);
    if (!ddos.empty())
        r.securityFindings.push_back("Possible DDoS from " + std::to_string(ddos.size()) + " IP(s).");

    // Recommendations
    if (!bf.empty())   r.recommendations.push_back("Block IPs with repeated failed logins immediately.");
    if (!ddos.empty()) r.recommendations.push_back("Enable rate limiting on suspicious IPs.");
    r.recommendations.push_back("Review all CRITICAL alerts within 1 hour.");
    r.recommendations.push_back("Update blocked IP list regularly.");

    return r;
}
