/*
 * ============================================================
 *  Network Monitoring & Log Analysis System
 *  Teyzix Core Internship — Task CPP-2
 *  Author  : Maha Nazeer
 *  Date    : June 2026
 * ============================================================
 */

#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <limits>
#include <algorithm>
#include <ctime>

#include "include/structures.h"
#include "include/log_processor.h"
#include "include/analyzer.h"
#include "include/report_generator.h"

// ---- Colour helpers (ANSI — work on Linux/macOS/Windows Terminal) ----
#define RESET   "\033[0m"
#define BOLD    "\033[1m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define CYAN    "\033[36m"
#define MAGENTA "\033[35m"

static std::string line(int n = 60, char c = '=') { return std::string(n, c); }

void printBanner() {
    std::cout << CYAN << BOLD;
    std::cout << "\n" << line() << "\n";
    std::cout << "   NETWORK MONITORING & LOG ANALYSIS SYSTEM\n";
    std::cout << "   Teyzix Core Internship  |  CPP-2\n";
    std::cout << line() << "\n" << RESET;
}

void printMenu() {
    std::cout << BOLD << "\n  MAIN MENU\n" << RESET;
    std::cout << line(60, '-') << "\n";
    std::cout << "  [1]  Load Log File\n";
    std::cout << "  [2]  View Activity Statistics\n";
    std::cout << "  [3]  Run Threat Detection\n";
    std::cout << "  [4]  Search / Filter Logs\n";
    std::cout << "  [5]  Generate & Export Report\n";
    std::cout << "  [6]  View All Logs\n";
    std::cout << "  [7]  View Alerts\n";
    std::cout << "  [0]  Exit\n";
    std::cout << line(60, '-') << "\n";
    std::cout << "  Enter choice: ";
}

void printLogsTable(const std::vector<NetworkLog>& logs, int maxRows = 30) {
    if (logs.empty()) { std::cout << YELLOW << "  No records found.\n" << RESET; return; }
    std::cout << "\n  " << std::left
              << std::setw(6)  << "ID"
              << std::setw(22) << "TIMESTAMP"
              << std::setw(17) << "SOURCE IP"
              << std::setw(17) << "DEST IP"
              << std::setw(12) << "EVENT"
              << std::setw(7)  << "CODE"
              << "MESSAGE\n";
    std::cout << "  " << line(100, '-') << "\n";

    int shown = 0;
    for (const auto& log : logs) {
        if (shown++ >= maxRows) { std::cout << "  ... (showing first " << maxRows << " rows)\n"; break; }
        std::string codeColor = (log.statusCode >= 500) ? RED :
                                (log.statusCode >= 400) ? YELLOW : GREEN;
        std::cout << "  " << std::left
                  << std::setw(6)  << log.id
                  << std::setw(22) << log.timestamp
                  << std::setw(17) << log.sourceIP
                  << std::setw(17) << log.destinationIP
                  << std::setw(12) << log.eventType
                  << codeColor << std::setw(7) << log.statusCode << RESET
                  << log.message.substr(0, 40) << "\n";
    }
    std::cout << "  Total: " << logs.size() << " record(s)\n";
}

void printAlertsTable(const std::vector<Alert>& alerts) {
    if (alerts.empty()) { std::cout << GREEN << "  No alerts detected.\n" << RESET; return; }
    std::cout << "\n  " << std::left
              << std::setw(8)  << "ID"
              << std::setw(20) << "TYPE"
              << std::setw(10) << "SEVERITY"
              << std::setw(17) << "SOURCE IP"
              << "DESCRIPTION\n";
    std::cout << "  " << line(90, '-') << "\n";

    for (const auto& a : alerts) {
        std::string sc = (a.severity == "CRITICAL") ? RED :
                         (a.severity == "HIGH")     ? YELLOW :
                         (a.severity == "MEDIUM")   ? MAGENTA : RESET;
        std::cout << "  " << std::left
                  << std::setw(8)  << a.alertID
                  << std::setw(20) << a.alertType
                  << sc << std::setw(10) << a.severity << RESET
                  << std::setw(17) << a.sourceIP
                  << a.description << "\n";
    }
    std::cout << "  Total: " << alerts.size() << " alert(s)\n";
}

// ---- Search submenu ----
void searchMenu(const Analyzer& analyzer) {
    std::cout << "\n  SEARCH & FILTER\n";
    std::cout << "  [1] Search by IP Address\n";
    std::cout << "  [2] Search by Date (YYYY-MM-DD)\n";
    std::cout << "  [3] Search by Event Type\n";
    std::cout << "  [4] Filter Suspicious Activities\n";
    std::cout << "  [5] Filter Error Records\n";
    std::cout << "  [0] Back\n";
    std::cout << "  Choice: ";

    int choice;
    std::cin >> choice;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    if (choice == 1) {
        std::cout << "  Enter IP: "; std::string ip; std::getline(std::cin, ip);
        printLogsTable(analyzer.searchByIP(ip));
    } else if (choice == 2) {
        std::cout << "  Enter Date (YYYY-MM-DD): "; std::string d; std::getline(std::cin, d);
        printLogsTable(analyzer.searchByDate(d));
    } else if (choice == 3) {
        std::cout << "  Event types: LOGIN, REQUEST, ERROR, BLOCKED, TRANSFER\n";
        std::cout << "  Enter type: "; std::string t; std::getline(std::cin, t);
        printLogsTable(analyzer.searchByEventType(t));
    } else if (choice == 4) {
        std::cout << "  Request threshold (default 100): "; int thr = 100; std::cin >> thr;
        printLogsTable(analyzer.filterSuspicious(thr));
    } else if (choice == 5) {
        printLogsTable(analyzer.filterErrors());
    }
}

int main() {
    printBanner();

    std::vector<NetworkLog> logs;
    ProcessingStats         pstats;
    std::vector<Alert>      alerts;
    bool logsLoaded = false;

    while (true) {
        printMenu();
        int choice;
        std::cin >> choice;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        // ---- EXIT ----
        if (choice == 0) {
            std::cout << CYAN << "\n  Goodbye! Stay secure.\n" << RESET;
            break;
        }

        // ---- LOAD FILE ----
        if (choice == 1) {
            std::cout << "  Enter log file path (or press Enter for default 'logs/network.csv'): ";
            std::string path; std::getline(std::cin, path);
            if (path.empty()) path = "logs/network.csv";

            pstats = ProcessingStats{};
            logs   = LogProcessor::loadFromFile(path, pstats);
            logsLoaded = !logs.empty();
            alerts.clear();

            if (logsLoaded) {
                std::cout << GREEN << "  [OK] Loaded " << pstats.validParsed << " valid records.\n" << RESET;
            } else {
                std::cout << RED << "  [ERROR] No valid records loaded. Check file path.\n" << RESET;
            }
            LogProcessor::printStats(pstats);
            continue;
        }

        if (!logsLoaded) {
            std::cout << RED << "  [!] Please load a log file first (Option 1).\n" << RESET;
            continue;
        }

        Analyzer analyzer(logs);

        // ---- STATISTICS ----
        if (choice == 2) {
            std::cout << "\n" << BOLD << "  ACTIVITY STATISTICS\n" << RESET;
            std::cout << line(60, '-') << "\n";
            std::cout << "  Total Requests    : " << analyzer.getTotalRequests() << "\n";
            std::cout << "  Unique IPs        : " << analyzer.getUniqueIPCount() << "\n";
            std::cout << "  Peak Hour         : " << analyzer.getPeakHour()      << "\n";

            auto top = analyzer.getMostActiveIP();
            std::cout << "  Most Active IP    : " << top.ip << " (" << top.totalRequests << " reqs)\n";

            std::cout << "\n  Top 10 IPs by Request Count:\n";
            std::cout << "  " << std::left << std::setw(18) << "IP"
                      << std::setw(10) << "REQUESTS"
                      << std::setw(10) << "ERRORS"
                      << "FAILED LOGINS\n";
            std::cout << "  " << line(50, '-') << "\n";
            auto ipStats = analyzer.getIPStats();
            int count = 0;
            for (const auto& s : ipStats) {
                if (count++ >= 10) break;
                std::cout << "  " << std::left
                          << std::setw(18) << s.ip
                          << std::setw(10) << s.totalRequests
                          << std::setw(10) << s.errorCount
                          << s.failedLogins << "\n";
            }

            std::cout << "\n  Error Code Frequency:\n";
            for (const auto& kv : analyzer.getErrorFrequency())
                std::cout << "    HTTP " << kv.first << " : " << kv.second << " occurrences\n";
        }

        // ---- THREAT DETECTION ----
        else if (choice == 3) {
            std::cout << YELLOW << "\n  Running threat detection...\n" << RESET;

            // Blocked IP list (configurable)
            std::vector<std::string> blockedList = {"10.0.0.99","192.168.1.200","172.16.0.50"};
            std::cout << "  Blocked IPs configured: ";
            for (const auto& ip : blockedList) std::cout << ip << " ";
            std::cout << "\n\n";

            alerts = analyzer.runAllDetections(blockedList);
            pstats.alertsGenerated = (int)alerts.size();
            printAlertsTable(alerts);
        }

        // ---- SEARCH ----
        else if (choice == 4) {
            searchMenu(analyzer);
        }

        // ---- REPORTS ----
        else if (choice == 5) {
            if (alerts.empty()) {
                std::cout << YELLOW << "  [!] Run Threat Detection first (Option 3) for full report.\n" << RESET;
            }
            Report report = analyzer.buildReport(alerts);
            report.corruptedLogs = pstats.corruptedSkipped;

            ReportGenerator::printReport(report, alerts);

            std::cout << "  Save reports to disk? (y/n): ";
            char ans; std::cin >> ans;
            if (ans == 'y' || ans == 'Y') {
                ReportGenerator::saveTextReport(report, alerts, "reports/monitoring_report.txt");
                ReportGenerator::saveCSVReport (report, alerts, "reports/monitoring_report.csv");
            }
        }

        // ---- VIEW ALL LOGS ----
        else if (choice == 6) {
            printLogsTable(logs, 50);
        }

        // ---- VIEW ALERTS ----
        else if (choice == 7) {
            printAlertsTable(alerts);
        }

        else {
            std::cout << RED << "  Invalid option.\n" << RESET;
        }
    }

    return 0;
}
