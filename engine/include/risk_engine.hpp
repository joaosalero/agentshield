#pragma once
#include "agentshield/sensor.h"
#include <string>
#include <vector>

namespace agentshield {
enum class Severity { info = 0, low = 1, medium = 2, high = 3, critical = 4 };
struct Finding { std::string rule_id, category, title, evidence, recommendation; Severity severity; int score; };
struct Assessment { as_snapshot snapshot{}; std::vector<Finding> findings; int risk_score = 0; Severity level = Severity::info; };
Assessment assess(const as_snapshot& snapshot);
std::string severity_name(Severity severity);
std::string to_json(const Assessment& assessment, long long timestamp_ms);
std::string to_tsv(const Assessment& assessment, long long timestamp_ms);
}
