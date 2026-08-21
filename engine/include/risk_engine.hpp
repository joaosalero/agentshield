#pragma once
#include "agentshield/sensor.h"
#include <istream>
#include <set>
#include <string>
#include <vector>

namespace agentshield {
enum class Severity { info = 0, low = 1, medium = 2, high = 3, critical = 4 };
enum class Privacy { standard, strict };
struct Finding { std::string rule_id, category, title, evidence, recommendation; Severity severity; int score; };
struct Assessment { as_snapshot snapshot{}; std::vector<Finding> findings; int risk_score = 0; Severity level = Severity::info; };
enum class ChangeDirection { granted, revoked };
struct ExposureChange { ChangeDirection direction; std::string category, identifier; Severity severity; bool attention; };
enum class PolicyAction { allow, approval, deny };
struct PolicyRule { std::string category, pattern; PolicyAction action; };
struct Policy {
    bool enforce = false;
    bool require_full_coverage = true;
    bool allow_root = false;
    bool allow_capabilities = false;
    int max_risk_score = 100;
    PolicyAction default_credential = PolicyAction::approval;
    PolicyAction default_sensitive_file = PolicyAction::approval;
    PolicyAction default_network = PolicyAction::approval;
    std::vector<PolicyRule> rules;
};
struct PolicyDecision { PolicyAction action; std::string category, identifier, reason; bool approved = false; bool blocking = false; };
struct PolicyEvaluation { std::vector<PolicyDecision> decisions; bool blocked = false; };
Assessment assess(const as_snapshot& snapshot);
std::vector<ExposureChange> detect_changes(const Assessment& previous, const Assessment& current);
Policy parse_policy(std::istream& input);
PolicyEvaluation evaluate_policy(const Assessment& assessment, const Policy& policy, const std::set<std::string>& approvals = {});
std::string severity_name(Severity severity);
std::string to_json(const Assessment& assessment, long long timestamp_ms, Privacy privacy = Privacy::standard, const std::vector<ExposureChange>& changes = {}, const PolicyEvaluation* policy = nullptr);
std::string to_tsv(const Assessment& assessment, long long timestamp_ms, Privacy privacy = Privacy::standard, const std::vector<ExposureChange>& changes = {}, const PolicyEvaluation* policy = nullptr);
}
