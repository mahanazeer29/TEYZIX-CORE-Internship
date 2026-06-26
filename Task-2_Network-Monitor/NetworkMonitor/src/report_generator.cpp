#include "../include/report_generator.h"
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>

static std::string line80(char c = '=') { return std::string(60, c); }

void ReportGenerator::printReport(const Report& report, const std::vector<Alert>& alerts) {
    std::cout << "\n" << line80() << "\n";
    std::cout << "       NETWORK MONITORING & LOG ANALYSIS REPORT\n";
    std::cout << line80() << "\n";
    std::cout << "  Generated  : " << report.generatedDate  << "\n";
    std::cout << "  Total Logs : " << report.totalLogs       << "\n";
    std::cout << "  Valid      : " << report.validLogs       << "\n";
    std::cout << "  Corrupted  : " << report.corruptedLogs   << "\n";
    std::cout << "  Unique IPs : " << report.uniqueIPs       << "\n";
    std::cout << "  Peak Hour  : " << report.peakHour        << "\n";
    std::cout << "  Top IP     : " << report.topActiveIP     << "\n";
    std::cout << line80('-') << "\n";
    std::cout << "  Total Alerts    : " << report.totalAlerts    << "\n";
    std::cout << "  Critical Alerts : " << report.criticalAlerts << "\n";
    std::cout << line80('-') << "\n";

    std::cout << "  SECURITY FINDINGS:\n";
    if (report.securityFindings.empty()) std::cout << "    None.\n";
    for (const auto& f : report.securityFindings) std::cout << "    [!] " << f << "\n";

    std::cout << "\n  RECOMMENDATIONS:\n";
    for (const auto& rec : report.recommendations) std::cout << "    -> " << rec << "\n";

    if (!alerts.empty()) {
        std::cout << "\n" << line80('-') << "\n";
        std::cout << "  ALERT DETAILS:\n";
        std::cout << "  " << std::left << std::setw(8) << "ID"
                  << std::setw(20) << "TYPE"
                  << std::setw(10) << "SEVERITY"
                  << std::setw(18) << "SOURCE IP"
                  << "DESCRIPTION\n";
        std::cout << "  " << line80('-') << "\n";
        for (const auto& a : alerts) {
            std::cout << "  " << std::left
                      << std::setw(8)  << a.alertID
                      << std::setw(20) << a.alertType
                      << std::setw(10) << a.severity
                      << std::setw(18) << a.sourceIP
                      << a.description << "\n";
        }
    }
    std::cout << line80() << "\n\n";
}

bool ReportGenerator::saveTextReport(const Report& report,
                                     const std::vector<Alert>& alerts,
                                     const std::string& outputPath) {
    std::ofstream f(outputPath);
    if (!f.is_open()) { std::cerr << "[ERROR] Cannot write report: " << outputPath << "\n"; return false; }

    f << line80() << "\n";
    f << "  NETWORK MONITORING & LOG ANALYSIS REPORT\n";
    f << line80() << "\n";
    f << "Generated    : " << report.generatedDate  << "\n";
    f << "Total Logs   : " << report.totalLogs       << "\n";
    f << "Valid Records: " << report.validLogs        << "\n";
    f << "Corrupted    : " << report.corruptedLogs    << "\n";
    f << "Unique IPs   : " << report.uniqueIPs        << "\n";
    f << "Peak Hour    : " << report.peakHour         << "\n";
    f << "Top Active IP: " << report.topActiveIP      << "\n";
    f << "Total Alerts : " << report.totalAlerts      << "\n";
    f << "Critical     : " << report.criticalAlerts   << "\n\n";

    f << "SECURITY FINDINGS:\n";
    for (const auto& s : report.securityFindings) f << "  [!] " << s << "\n";
    f << "\nRECOMMENDATIONS:\n";
    for (const auto& r : report.recommendations) f << "  -> " << r << "\n";

    f << "\nALERT DETAILS:\n";
    for (const auto& a : alerts) {
        f << "  [" << a.alertID << "] " << a.alertType << " | " << a.severity
          << " | " << a.sourceIP << " | " << a.description << "\n";
    }
    f << line80() << "\n";
    f.close();
    std::cout << "[OK]  Text report saved: " << outputPath << "\n";
    return true;
}

bool ReportGenerator::saveCSVReport(const Report& report,
                                    const std::vector<Alert>& alerts,
                                    const std::string& outputPath) {
    std::ofstream f(outputPath);
    if (!f.is_open()) { std::cerr << "[ERROR] Cannot write CSV: " << outputPath << "\n"; return false; }

    // Summary section
    f << "SECTION,KEY,VALUE\n";
    f << "SUMMARY,Generated Date," << report.generatedDate  << "\n";
    f << "SUMMARY,Total Logs,"     << report.totalLogs       << "\n";
    f << "SUMMARY,Valid Records,"  << report.validLogs        << "\n";
    f << "SUMMARY,Corrupted,"      << report.corruptedLogs    << "\n";
    f << "SUMMARY,Unique IPs,"     << report.uniqueIPs        << "\n";
    f << "SUMMARY,Peak Hour,"      << report.peakHour         << "\n";
    f << "SUMMARY,Top Active IP,"  << report.topActiveIP      << "\n";
    f << "SUMMARY,Total Alerts,"   << report.totalAlerts      << "\n";
    f << "SUMMARY,Critical Alerts,"<< report.criticalAlerts   << "\n\n";

    // Alerts section
    f << "ALERT_ID,ALERT_TYPE,SEVERITY,SOURCE_IP,DESCRIPTION,TIMESTAMP\n";
    for (const auto& a : alerts) {
        f << a.alertID    << ","
          << a.alertType  << ","
          << a.severity   << ","
          << a.sourceIP   << ","
          << "\"" << a.description << "\","
          << a.timestamp  << "\n";
    }
    f.close();
    std::cout << "[OK]  CSV report saved : " << outputPath << "\n";
    return true;
}
