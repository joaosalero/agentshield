#include "audit_log.hpp"
#include "risk_engine.hpp"
#include <algorithm>
#include <cassert>
#include <cstring>
#include <iostream>
#include <sstream>

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

    std::istringstream policy_text(
        "version 1\nmode enforce\nrequire-full-coverage true\nallow-root false\n"
        "allow-capabilities false\nmax-risk-score 100\n"
        "default credential approval\ndefault sensitive-file approval\ndefault network allow\n");
    auto policy = agentshield::parse_policy(policy_text);
    auto policy_blocked = agentshield::evaluate_policy(assessment, policy);
    assert(policy_blocked.blocked && policy_blocked.decisions.size() == 2);
    std::set<std::string> approvals{"credential:SYNTHETIC_DEMO_TOKEN_NAME", "filesystem:/tmp/file\tFINDING\tforged"};
    auto policy_approved = agentshield::evaluate_policy(assessment, policy, approvals);
    assert(!policy_approved.blocked && policy_approved.decisions.size() == 2);
    for (const auto& decision : policy_approved.decisions) assert(decision.approved && !decision.blocking);
    auto strict_policy_json = agentshield::to_json(assessment, 3, agentshield::Privacy::strict, {}, &policy_blocked);
    assert(strict_policy_json.find("SYNTHETIC_DEMO_TOKEN_NAME") == std::string::npos);
    assert(strict_policy_json.find("/tmp/file") == std::string::npos);
    auto strict_policy_tsv = agentshield::to_tsv(assessment, 3, agentshield::Privacy::strict, {}, &policy_blocked);
    assert(strict_policy_tsv.find("SYNTHETIC_DEMO_TOKEN_NAME") == std::string::npos);
    assert(strict_policy_tsv.find("/tmp/file") == std::string::npos);
    assert(strict_policy_tsv.find("\tFINDING\tforged") == std::string::npos);

    std::istringstream deny_text(
        "version 1\nmode enforce\nrequire-full-coverage true\nallow-root false\n"
        "allow-capabilities false\nmax-risk-score 100\ndefault credential allow\n"
        "default sensitive-file allow\ndefault network allow\ncredential SYNTHETIC_DEMO_TOKEN_NAME deny\n");
    auto deny_policy = agentshield::parse_policy(deny_text);
    auto denied = agentshield::evaluate_policy(assessment, deny_policy, approvals);
    assert(denied.blocked && denied.decisions.size() == 1 && !denied.decisions[0].approved);

    auto expect_invalid=[](const std::string& text){bool invalid=false;try{std::istringstream input(text);(void)agentshield::parse_policy(input);}catch(const std::invalid_argument&){invalid=true;}assert(invalid);};
    expect_invalid("version 2\n");
    expect_invalid("mode audit\n");
    expect_invalid("version 1\nunknown value\n");
    expect_invalid("version 1\nmode audit\nmode enforce\n");
    expect_invalid("version 1\nallow-root maybe\n");
    expect_invalid("version 1\nresource-prefix relative allow\n");
    expect_invalid("version 1\n#"+std::string(5000,'x')+"\n");

    auto restrictive=policy;
    as_snapshot no_coverage=baseline;no_coverage.coverage=0;
    assert(agentshield::evaluate_policy(agentshield::assess(no_coverage),restrictive).blocked);
    as_snapshot root_snapshot=baseline;root_snapshot.effective_uid=0;
    assert(agentshield::evaluate_policy(agentshield::assess(root_snapshot),restrictive).blocked);
    as_snapshot caps_snapshot=baseline;caps_snapshot.effective_capabilities=1;
    assert(agentshield::evaluate_policy(agentshield::assess(caps_snapshot),restrictive).blocked);
    restrictive.max_risk_score=39;
    assert(agentshield::evaluate_policy(assessment,restrictive,approvals).blocked);

    std::istringstream prefix_text(
        "version 1\nmode enforce\nrequire-full-coverage true\nallow-root false\n"
        "allow-capabilities false\nmax-risk-score 100\ndefault credential allow\n"
        "default sensitive-file approval\ndefault network approval\n"
        "resource-prefix /tmp/ allow\nresource-prefix /tmp/file deny\n");
    auto prefix_policy=agentshield::parse_policy(prefix_text);
    auto prefix_denied=agentshield::evaluate_policy(assessment,prefix_policy,approvals);
    assert(prefix_denied.blocked&&prefix_denied.decisions.size()==1&&prefix_denied.decisions[0].action==agentshield::PolicyAction::deny);

    as_snapshot socket_snapshot=baseline;socket_snapshot.resource_count=1;std::strcpy(socket_snapshot.resources[0].path,"socket:[123]");socket_snapshot.resources[0].kind=AS_RESOURCE_SOCKET;socket_snapshot.resources[0].risk=2;
    auto network_policy=policy;network_policy.default_network=agentshield::PolicyAction::approval;
    auto network_approved=agentshield::evaluate_policy(agentshield::assess(socket_snapshot),network_policy,{"network:*"});
    assert(!network_approved.blocked&&network_approved.decisions.size()==1&&network_approved.decisions[0].approved);

    as_snapshot incomplete{};
    incomplete.pid = 43;
    auto unknown = agentshield::assess(incomplete);
    assert(unknown.risk_score == 75);
    assert(unknown.level == agentshield::Severity::critical);
    assert(unknown.findings.size() == 3);

    assert(agentshield::sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    agentshield::AuditKey audit_key{};
    std::fill(audit_key.begin(), audit_key.begin() + 20, 0x0b);
    assert(agentshield::hmac_sha256_hex(audit_key, "Hi There") == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    agentshield::AuditRecord first{1, 10, std::string(64, '0'), "", "{}", ""};
    std::string first_line = agentshield::encode_audit_record(first, audit_key);
    auto decoded_first = agentshield::decode_audit_record(first_line.substr(0, first_line.size() - 1));
    agentshield::AuditRecord second{2, 11, decoded_first.mac, "", "{\"event\":2}\n", ""};
    std::string chain = first_line + agentshield::encode_audit_record(second, audit_key);
    std::istringstream audit_input(chain);
    std::vector<agentshield::AuditRecord> audit_records;
    auto verified = agentshield::verify_audit_stream(audit_input, audit_key, &audit_records);
    assert(verified.records == 2 && verified.final_mac == audit_records[1].mac);
    assert(agentshield::helix_export_json(audit_records[0]).find("io.helix-sentinel.agentshield/v1") != std::string::npos);
    std::string noncanonical = first_line;
    auto padded = noncanonical.find("e30=");
    assert(padded != std::string::npos);
    noncanonical[padded + 2] = '1';
    bool padding_rejected = false;
    try { (void)agentshield::decode_audit_record(noncanonical.substr(0, noncanonical.size() - 1)); }
    catch (const std::invalid_argument&) { padding_rejected = true; }
    assert(padding_rejected);
    bool tamper_rejected = false;
    chain[chain.find("eventBase64") + 14] = chain[chain.find("eventBase64") + 14] == 'A' ? 'B' : 'A';
    try { std::istringstream tampered(chain); (void)agentshield::verify_audit_stream(tampered, audit_key); }
    catch (const std::invalid_argument&) { tamper_rejected = true; }
    assert(tamper_rejected);
    std::cout << "risk engine: OK\n";
}
