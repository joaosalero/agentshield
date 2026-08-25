#include "risk_engine.hpp"
#include <cassert>
#include <cstring>
#include <iostream>

namespace {
as_snapshot snapshot_with_credentials(std::size_t count) {
    as_snapshot snapshot{};
    snapshot.coverage = AS_COVERAGE_STATUS | AS_COVERAGE_ENVIRONMENT | AS_COVERAGE_RESOURCES;
    snapshot.pid = 77;
    snapshot.effective_uid = 1000;
    snapshot.credential_count = count;
    for (std::size_t i = 0; i < count; ++i) {
        std::strcpy(snapshot.credentials[i].name, "SYNTHETIC_EVAL_NAME");
        snapshot.credentials[i].risk = 1;
    }
    return snapshot;
}
}

int main() {
    int false_positives = 0, normal_observations = 0, detected_surges = 0;
    constexpr int scenarios = 20;
    for (int scenario = 0; scenario < scenarios; ++scenario) {
        agentshield::BehaviorBaseline baseline;
        for (int sample = 0; sample < 12; ++sample) {
            auto signal = baseline.observe(agentshield::assess(snapshot_with_credentials(static_cast<std::size_t>(sample % 2))));
            if (signal.warmed_up) { ++normal_observations; if (signal.anomalous) ++false_positives; }
        }
        auto surge = baseline.observe(agentshield::assess(snapshot_with_credentials(5)));
        if (surge.anomalous && surge.anomaly_score >= 60 && surge.feature == "credential count") ++detected_surges;
    }
    double false_positive_rate = normal_observations ? static_cast<double>(false_positives) / normal_observations : 1.0;
    double detection_rate = static_cast<double>(detected_surges) / scenarios;
    assert(false_positive_rate <= 0.05);
    assert(detection_rate >= 0.95);
    std::cout << "behavior evaluation: false-positive-rate=" << false_positive_rate
              << " detection-rate=" << detection_rate << " scenarios=" << scenarios << "\n";
}
