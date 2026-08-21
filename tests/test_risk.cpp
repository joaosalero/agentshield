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

    as_snapshot baseline = snapshot;
    baseline.credential_count = 0;
    baseline.resource_count = 0;
    auto changes = agentshield::detect_changes(agentshield::assess(baseline), assessment);
    assert(changes.size() == 2);
    assert(changes[0].direction == agentshield::ChangeDirection::granted);
    assert(changes[0].attention);
    auto change_json = agentshield::to_json(assessment, 2, agentshield::Privacy::strict, changes);
    assert(change_json.find("\"changes\":[{") != std::string::npos);
    assert(change_json.find("SYNTHETIC_DEMO_TOKEN_NAME") == std::string::npos);
    assert(change_json.find("/tmp/file") == std::string::npos);
    auto change_tsv = agentshield::to_tsv(assessment, 2, agentshield::Privacy::standard, changes);
    assert(change_tsv.find("CHANGE\t2\tGRANTED\tHIGH\tcredential\tSYNTHETIC_DEMO_TOKEN_NAME\tATTENTION") != std::string::npos);
    assert(change_tsv.find("\tFINDING\tforged") == std::string::npos);
    auto strict_change_tsv = agentshield::to_tsv(assessment, 2, agentshield::Privacy::strict, changes);
    assert(strict_change_tsv.find("SYNTHETIC_DEMO_TOKEN_NAME") == std::string::npos);
    assert(strict_change_tsv.find("/tmp/file") == std::string::npos);
    auto revoked = agentshield::detect_changes(assessment, agentshield::assess(baseline));
    assert(revoked.size() == 2);
    bool credential_revoked = false, filesystem_revoked = false;
    for (const auto& change : revoked) {
        assert(!change.attention && change.direction == agentshield::ChangeDirection::revoked);
        credential_revoked |= change.category == "credential" && change.identifier == "SYNTHETIC_DEMO_TOKEN_NAME";
        filesystem_revoked |= change.category == "filesystem" && change.identifier.find("/tmp/file") == 0;
    }
    assert(credential_revoked && filesystem_revoked);

    as_snapshot obscured = snapshot;
    obscured.coverage = AS_COVERAGE_STATUS;
    obscured.credential_count = 0;
    obscured.resource_count = 0;
    auto coverage_lost = agentshield::detect_changes(assessment, agentshield::assess(obscured));
    assert(coverage_lost.size() == 1);
    assert(coverage_lost[0].category == "observability" && coverage_lost[0].attention);
    auto coverage_restored = agentshield::detect_changes(agentshield::assess(obscured), assessment);
    assert(coverage_restored.size() == 1);
    assert(coverage_restored[0].category == "observability" && !coverage_restored[0].attention);

    as_snapshot privileged = baseline;
    privileged.effective_uid = 0;
    privileged.effective_capabilities = 3;
    auto privilege_changes = agentshield::detect_changes(agentshield::assess(baseline), agentshield::assess(privileged));
    assert(privilege_changes.size() == 3);
    assert(privilege_changes[0].attention);
    auto privilege_removed = agentshield::detect_changes(agentshield::assess(privileged), agentshield::assess(baseline));
    assert(privilege_removed.size() == 3);
    assert(!privilege_removed[0].attention);

    as_snapshot incomplete{};
    incomplete.pid = 43;
    auto unknown = agentshield::assess(incomplete);
    assert(unknown.risk_score == 75);
    assert(unknown.level == agentshield::Severity::critical);
    assert(unknown.findings.size() == 3);
    std::cout << "risk engine: OK\n";
}
