#pragma once
#include "structures.h"
#include <string>
#include <vector>

class LogProcessor {
public:
    // Load and parse a CSV log file
    static std::vector<NetworkLog> loadFromFile(const std::string& filepath,
                                                 ProcessingStats& stats);

    // Parse a single CSV line into a NetworkLog
    static NetworkLog parseLine(const std::string& line, int lineNum);

    // Validate a parsed log entry
    static bool validateLog(const NetworkLog& log);

    // Print processing summary
    static void printStats(const ProcessingStats& stats);
};
