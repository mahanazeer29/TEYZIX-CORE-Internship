#pragma once
#include "structures.h"
#include <string>
#include <vector>

class ReportGenerator {
public:
    // Save report as plain-text .txt
    static bool saveTextReport(const Report& report,
                               const std::vector<Alert>& alerts,
                               const std::string& outputPath);

    // Save report as CSV
    static bool saveCSVReport(const Report& report,
                              const std::vector<Alert>& alerts,
                              const std::string& outputPath);

    // Print report to console
    static void printReport(const Report& report, const std::vector<Alert>& alerts);
};
