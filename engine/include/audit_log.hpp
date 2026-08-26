#pragma once

#include <array>
#include <cstdint>
#include <istream>
#include <ostream>
#include <string>
#include <vector>

namespace agentshield {

using AuditKey = std::array<std::uint8_t, 32>;

struct AuditRecord {
    std::uint64_t sequence = 0;
    std::int64_t recorded_at_ms = 0;
    std::string previous_mac;
    std::string event_sha256;
    std::string event_json;
    std::string mac;
};

struct AuditVerification {
    std::uint64_t records = 0;
    std::string final_mac;
};

std::string audit_key_to_hex(const AuditKey& key);
AuditKey audit_key_from_hex(const std::string& text);
std::string sha256_hex(const std::string& value);
std::string hmac_sha256_hex(const AuditKey& key, const std::string& value);
std::string encode_audit_record(const AuditRecord& record, const AuditKey& key);
AuditRecord decode_audit_record(const std::string& line);
AuditVerification verify_audit_stream(std::istream& input, const AuditKey& key,
                                      std::vector<AuditRecord>* records = nullptr);
std::string helix_export_json(const AuditRecord& record);

}  // namespace agentshield
