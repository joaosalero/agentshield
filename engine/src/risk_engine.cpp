#include "risk_engine.hpp"
#include <algorithm>
#include <sstream>

namespace agentshield {
namespace {
Severity severity_from(unsigned value) { return static_cast<Severity>(std::min(value, 4U)); }
std::string escape(const std::string& value) {
    std::ostringstream out;
    for (unsigned char c : value) {
        switch (c) { case '\"': out << "\\\""; break; case '\\': out << "\\\\"; break; case '\n': out << "\\n"; break; case '\r': out << "\\r"; break; case '\t': out << "\\t"; break; default: if (c >= 0x20) out << c; }
    }
    return out.str();
}
std::string tsv_field(std::string value) {
    for (char& c : value) if (c == '\t' || c == '\n' || c == '\r') c = ' ';
    return value;
}
void add(Assessment& a, std::string id, Severity severity, int score, std::string category, std::string title, std::string evidence, std::string recommendation) {
    a.findings.push_back({std::move(id),std::move(category),std::move(title),std::move(evidence),std::move(recommendation),severity,score});
}
}

std::string severity_name(Severity s) {
    static const char* names[] = {"INFO","LOW","MEDIUM","HIGH","CRITICAL"};
    return names[static_cast<unsigned>(s)];
}

Assessment assess(const as_snapshot& snapshot) {
    Assessment a; a.snapshot = snapshot;
    if (snapshot.effective_uid == 0) add(a,"AS-PRIV-001",Severity::critical,40,"privilege","Agent runs as root","effective UID is 0","Run the agent as an unprivileged user or inside a restricted sandbox.");
    if (snapshot.effective_capabilities) add(a,"AS-PRIV-002",Severity::high,25,"privilege","Linux capabilities are active","CapEff is non-zero","Drop every capability that is not explicitly required.");
    for (size_t i=0;i<snapshot.credential_count;++i) {
        const auto& c=snapshot.credentials[i]; Severity s=severity_from(c.risk);
        add(a,"AS-CRED-001",s,c.risk>=4?30:c.risk>=3?20:10,"credential","Credential-like environment variable is exposed",c.name,"Remove it from the agent environment or provide a scoped, short-lived credential.");
    }
    for (size_t i=0;i<snapshot.resource_count;++i) {
        const auto& r=snapshot.resources[i]; Severity s=severity_from(r.risk);
        std::string title=r.kind==AS_RESOURCE_SOCKET?"Agent has an open network socket":"Agent has a sensitive file open";
        add(a,r.kind==AS_RESOURCE_SOCKET?"AS-NET-001":"AS-FILE-001",s,r.kind==AS_RESOURCE_SOCKET?8:20,r.kind==AS_RESOURCE_SOCKET?"network":"filesystem",title,r.path,r.kind==AS_RESOURCE_SOCKET?"Confirm the destination and enforce an outbound allowlist.":"Close the file and restrict the agent filesystem scope.");
    }
    if (snapshot.truncated_items) add(a,"AS-OBS-001",Severity::medium,10,"observability","Snapshot exceeded collection limits",std::to_string(snapshot.truncated_items)+" items omitted","Reduce exposed resources or increase the sensor limit after review.");
    std::sort(a.findings.begin(),a.findings.end(),[](const Finding& x,const Finding& y){return x.severity>y.severity || (x.severity==y.severity && x.title<y.title);});
    for(const auto& f:a.findings) a.risk_score=std::min(100,a.risk_score+f.score);
    a.level=a.risk_score>=75?Severity::critical:a.risk_score>=50?Severity::high:a.risk_score>=25?Severity::medium:a.risk_score>0?Severity::low:Severity::info;
    for (const auto& finding : a.findings) {
        if (finding.severity > a.level) a.level = finding.severity;
    }
    return a;
}

std::string to_json(const Assessment& a, long long timestamp_ms) {
    std::ostringstream o;
    o << "{\"schema\":\"io.agentshield.snapshot/v1\",\"timestampMs\":"<<timestamp_ms<<",\"process\":{\"pid\":"<<a.snapshot.pid<<",\"parentPid\":"<<a.snapshot.parent_pid<<",\"name\":\""<<escape(a.snapshot.process_name)<<"\",\"executable\":\""<<escape(a.snapshot.executable)<<"\",\"workingDirectory\":\""<<escape(a.snapshot.working_directory)<<"\",\"effectiveUid\":"<<a.snapshot.effective_uid<<",\"effectiveCapabilities\":\""<<std::hex<<a.snapshot.effective_capabilities<<std::dec<<"\"},\"risk\":{\"score\":"<<a.risk_score<<",\"level\":\""<<severity_name(a.level)<<"\"},\"credentials\":[";
    for(size_t i=0;i<a.snapshot.credential_count;++i){if(i)o<<',';const auto& c=a.snapshot.credentials[i];o<<"{\"name\":\""<<escape(c.name)<<"\",\"severity\":\""<<severity_name(severity_from(c.risk))<<"\"}";}
    o << "],\"resources\":[";
    for(size_t i=0;i<a.snapshot.resource_count;++i){if(i)o<<',';const auto& r=a.snapshot.resources[i];o<<"{\"kind\":\""<<as_resource_kind_name(r.kind)<<"\",\"identifier\":\""<<escape(r.path)<<"\",\"severity\":\""<<severity_name(severity_from(r.risk))<<"\"}";}
    o << "],\"findings\":[";
    for(size_t i=0;i<a.findings.size();++i){if(i)o<<',';const auto& f=a.findings[i];o<<"{\"ruleId\":\""<<f.rule_id<<"\",\"category\":\""<<f.category<<"\",\"severity\":\""<<severity_name(f.severity)<<"\",\"score\":"<<f.score<<",\"title\":\""<<escape(f.title)<<"\",\"evidence\":\""<<escape(f.evidence)<<"\",\"recommendation\":\""<<escape(f.recommendation)<<"\"}";}
    o << "]}\n"; return o.str();
}

std::string to_tsv(const Assessment& a,long long timestamp_ms) {
    std::ostringstream o;o<<"SNAPSHOT\t"<<timestamp_ms<<'\t'<<a.snapshot.pid<<'\t'<<a.risk_score<<'\t'<<severity_name(a.level)<<'\t'<<tsv_field(a.snapshot.process_name)<<'\t'<<a.snapshot.effective_uid<<'\t'<<std::hex<<a.snapshot.effective_capabilities<<std::dec<<'\t'<<tsv_field(a.snapshot.executable)<<'\n';
    for(size_t i=0;i<a.snapshot.credential_count;++i){const auto& c=a.snapshot.credentials[i];o<<"CREDENTIAL\t"<<severity_name(severity_from(c.risk))<<'\t'<<tsv_field(c.name)<<"\tEnvironment variable name only; value was not retained or emitted\n";}
    for(size_t i=0;i<a.snapshot.resource_count;++i){const auto& r=a.snapshot.resources[i];o<<"RESOURCE\t"<<severity_name(severity_from(r.risk))<<'\t'<<as_resource_kind_name(r.kind)<<'\t'<<tsv_field(r.path)<<'\n';}
    for(const auto& f:a.findings)o<<"FINDING\t"<<severity_name(f.severity)<<'\t'<<tsv_field(f.rule_id)<<'\t'<<tsv_field(f.title)<<'\t'<<tsv_field(f.evidence)<<'\t'<<tsv_field(f.recommendation)<<'\n';
    o<<"END\n";return o.str();
}
}
