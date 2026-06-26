#include "../include/log_processor.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>

// Helper: trim whitespace
static std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    size_t end   = s.find_last_not_of(" \t\r\n");
    return (start == std::string::npos) ? "" : s.substr(start, end - start + 1);
}

// Helper: split CSV line respecting quotes
static std::vector<std::string> splitCSV(const std::string& line) {
    std::vector<std::string> fields;
    std::string field;
    bool inQuotes = false;
    for (char c : line) {
        if (c == '"') { inQuotes = !inQuotes; }
        else if (c == ',' && !inQuotes) { fields.push_back(trim(field)); field.clear(); }
        else { field += c; }
    }
    fields.push_back(trim(field));
    return fields;
}

NetworkLog LogProcessor::parseLine(const std::string& line, int lineNum) {
    NetworkLog log;
    log.id    = lineNum;
    log.valid = false;

    auto fields = splitCSV(line);
    // Expected columns: timestamp, sourceIP, destinationIP, eventType, statusCode, message
    if (fields.size() < 6) return log;

    try {
        log.timestamp      = fields[0];
        log.sourceIP       = fields[1];
        log.destinationIP  = fields[2];
        log.eventType      = fields[3];
        log.statusCode     = std::stoi(fields[4]);
        log.message        = fields[5];
        log.valid          = true;
    } catch (...) {
        log.valid = false;
    }
    return log;
}

bool LogProcessor::validateLog(const NetworkLog& log) {
    if (!log.valid) return false;
    if (log.timestamp.empty() || log.sourceIP.empty()) return false;
    if (log.statusCode < 100 || log.statusCode > 599) return false;
    // Basic IP format check (contains dots)
    if (log.sourceIP.find('.') == std::string::npos) return false;
    return true;
}

std::vector<NetworkLog> LogProcessor::loadFromFile(const std::string& filepath,
                                                    ProcessingStats& stats) {
    std::vector<NetworkLog> logs;
    std::ifstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "[ERROR] Cannot open file: " << filepath << "\n";
        return logs;
    }

    std::string line;
    int lineNum = 0;
    bool firstLine = true;

    while (std::getline(file, line)) {
        lineNum++;
        if (firstLine) { firstLine = false; continue; } // skip header
        if (line.empty()) continue;

        stats.totalRead++;
        NetworkLog log = parseLine(line, lineNum);

        if (validateLog(log)) {
            stats.validParsed++;
            logs.push_back(log);
        } else {
            stats.corruptedSkipped++;
            std::cerr << "[WARN]  Corrupted record at line " << lineNum << " — skipped.\n";
        }
    }
    file.close();
    return logs;
}

void LogProcessor::printStats(const ProcessingStats& stats) {
    std::cout << "\n========================================\n";
    std::cout << "       LOG PROCESSING STATISTICS        \n";
    std::cout << "========================================\n";
    std::cout << "  Total Lines Read   : " << stats.totalRead        << "\n";
    std::cout << "  Valid Records      : " << stats.validParsed       << "\n";
    std::cout << "  Corrupted Skipped  : " << stats.corruptedSkipped  << "\n";
    std::cout << "  Alerts Generated   : " << stats.alertsGenerated   << "\n";
    std::cout << "========================================\n\n";
}
