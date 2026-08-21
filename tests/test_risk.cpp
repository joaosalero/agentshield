#include "risk_engine.hpp"
#include <cassert>
#include <cstring>
#include <iostream>

int main() {
    as_snapshot snapshot{};
    snapshot.coverage = AS_COVERAGE_STATUS | AS_COVERAGE_ENVIRONMENT | AS_COVERAGE_RESOURCES;
    snapshot.pid = 42;
    snapshot.effective_uid = 1000;
    std::strcpy(snapshot.process_name, "private-agent-name");
    std::strcpy(snapshot.executable, "/private/bin/agent");
    std::strcpy(snapshot.working_directory, "/private/work");
    snapshot.credential_count = 1;
    std::strcpy(snapshot.credentials[0].name, "SYNTHETIC_DEMO_TOKEN_NAME");
    snapshot.credentials[0].risk = 3;
    snapshot.resource_count = 1;
    std::strcpy(snapshot.resources[0].path, "/tmp/file\tFINDING\tforged");
    snapshot.resources[0].kind = AS_RESOURCE_SENSITIVE_FILE;
    snapshot.resources[0].risk = 3;

    auto assessment = agentshield::assess(snapshot);
    assert(assessment.risk_score == 40);
    assert(assessment.level == agentshield::Severity::high);
    assert(assessment.findings.size() == 2);

    auto json = agentshield::to_json(assessment, 1);
    assert(json.find("SYNTHETIC_DEMO_TOKEN_NAME") != std::string::npos);
    auto strict = agentshield::to_json(assessment, 1, agentshield::Privacy::strict);
    assert(strict.find("SYNTHETIC_DEMO_TOKEN_NAME") == std::string::npos);
    assert(strict.find("private-agent-name") == std::string::npos);
    assert(strict.find("/private/") == std::string::npos);

    auto tsv = agentshield::to_tsv(assessment, 1);
    assert(tsv.find("CREDENTIAL\tHIGH\tSYNTHETIC_DEMO_TOKEN_NAME") != std::string::npos);
    assert(tsv.find("\tFINDING\tforged") == std::string::npos);

    as_snapshot incomplete{};
    incomplete.pid = 43;
    auto unknown = agentshield::assess(incomplete);
    assert(unknown.risk_score == 75);
    assert(unknown.level == agentshield::Severity::critical);
    assert(unknown.findings.size() == 3);
    std::cout << "risk engine: OK\n";
}
