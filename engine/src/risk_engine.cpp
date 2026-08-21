#include "risk_engine.hpp"
#include <algorithm>
#include <cctype>
#include <iomanip>
#include <map>
#include <sstream>
#include <stdexcept>

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
std::string change_key(const std::string& category, const std::string& identifier) { return category + "\x1f" + identifier; }
std::string direction_name(ChangeDirection direction) { return direction == ChangeDirection::granted ? "GRANTED" : "REVOKED"; }
std::string private_change_identifier(const ExposureChange& change, Privacy privacy) {
    if (privacy != Privacy::strict) return change.identifier;
    if (change.category == "credential") return "[credential name redacted]";
    if (change.category == "filesystem" || change.category == "network") return "[resource identifier redacted]";
    return change.identifier;
}
std::string action_name(PolicyAction action) { return action==PolicyAction::allow?"ALLOW":action==PolicyAction::approval?"APPROVAL":"DENY"; }
PolicyAction parse_action(const std::string& value) {
    if(value=="allow")return PolicyAction::allow;
    if(value=="approval")return PolicyAction::approval;
    if(value=="deny")return PolicyAction::deny;
    throw std::invalid_argument("policy action must be allow, approval, or deny");
}
bool parse_bool(const std::string& value) {
    if(value=="true")return true;
    if(value=="false")return false;
    throw std::invalid_argument("policy boolean must be true or false");
}
void require_end(std::istringstream& line) { std::string extra;if(line>>extra)throw std::invalid_argument("unexpected policy token: "+extra); }
bool valid_credential_name(const std::string& value) {
    if(value.empty()||!(std::isalpha(static_cast<unsigned char>(value[0]))||value[0]=='_'))return false;
    return std::all_of(value.begin()+1,value.end(),[](unsigned char c){return std::isalnum(c)||c=='_';});
}
PolicyAction rule_action(const Policy& policy,const std::string& category,const std::string& identifier,PolicyAction fallback) {
    const PolicyRule* best=nullptr;
    for(const auto& rule:policy.rules){
        if(rule.category!=category)continue;
        bool matches=rule.prefix_match?identifier.compare(0,rule.pattern.size(),rule.pattern)==0:rule.pattern==identifier;
        if(matches&&(!best||rule.pattern.size()>best->pattern.size()))best=&rule;
    }
    return best?best->action:fallback;
}
std::string private_policy_identifier(const PolicyDecision& decision,Privacy privacy){
    if(privacy!=Privacy::strict)return decision.identifier;
    if(decision.category=="credential")return "[credential name redacted]";
    if(decision.category=="filesystem"||decision.category=="network")return "[resource identifier redacted]";
    return decision.identifier;
}
void add_policy_decision(PolicyEvaluation& evaluation,PolicyAction action,std::string category,std::string identifier,std::string reason,const Policy& policy,const std::set<std::string>& approvals){
    if(action==PolicyAction::allow)return;
    std::string exact=category+":"+identifier,wildcard=category+":*";
    bool approved=action==PolicyAction::approval&&(approvals.count(exact)||approvals.count(wildcard));
    bool blocking=policy.enforce&&!approved;
    evaluation.decisions.push_back({action,std::move(category),std::move(identifier),std::move(reason),approved,blocking});
    evaluation.blocked|=blocking;
}
}

std::string severity_name(Severity s) {
    static const char* names[] = {"INFO","LOW","MEDIUM","HIGH","CRITICAL"};
    return names[static_cast<unsigned>(s)];
}

Assessment assess(const as_snapshot& snapshot) {
    Assessment a; a.snapshot = snapshot;
    if (!(snapshot.coverage & AS_COVERAGE_STATUS)) add(a,"AS-OBS-STATUS",Severity::high,25,"observability","Privilege metadata was not observable","/proc status unavailable","Treat this snapshot as incomplete and restore process-inspection permission.");
    if (!(snapshot.coverage & AS_COVERAGE_ENVIRONMENT)) add(a,"AS-OBS-ENV",Severity::high,25,"observability","Credential environment was not observable","/proc environment unavailable","Treat credential exposure as unknown, not empty.");
    if (!(snapshot.coverage & AS_COVERAGE_RESOURCES)) add(a,"AS-OBS-RESOURCE",Severity::high,25,"observability","Open resources were not observable","/proc descriptors unavailable","Treat file and network exposure as unknown, not empty.");
    if ((snapshot.coverage & AS_COVERAGE_STATUS) && snapshot.effective_uid == 0) add(a,"AS-PRIV-001",Severity::critical,40,"privilege","Agent runs as root","effective UID is 0","Run the agent as an unprivileged user or inside a restricted sandbox.");
    if ((snapshot.coverage & AS_COVERAGE_STATUS) && snapshot.effective_capabilities) add(a,"AS-PRIV-002",Severity::high,25,"privilege","Linux capabilities are active","CapEff is non-zero","Drop every capability that is not explicitly required.");
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

std::vector<ExposureChange> detect_changes(const Assessment& previous, const Assessment& current) {
    std::map<std::string, ExposureChange> before, after;
    auto credential_entries=[](const Assessment& assessment, std::map<std::string,ExposureChange>& entries){
        for(size_t i=0;i<assessment.snapshot.credential_count;++i){const auto& c=assessment.snapshot.credentials[i];ExposureChange change{ChangeDirection::granted,"credential",c.name,severity_from(c.risk),c.risk>=3};entries.emplace(change_key(change.category,change.identifier),change);}
    };
    auto resource_entries=[](const Assessment& assessment, std::map<std::string,ExposureChange>& entries){
        for(size_t i=0;i<assessment.snapshot.resource_count;++i){const auto& r=assessment.snapshot.resources[i];std::string category=r.kind==AS_RESOURCE_SOCKET?"network":"filesystem";ExposureChange change{ChangeDirection::granted,category,r.path,severity_from(r.risk),r.risk>=3};entries.emplace(change_key(change.category,change.identifier),change);}
    };
    bool comparable_environment=(previous.snapshot.coverage&AS_COVERAGE_ENVIRONMENT)&&(current.snapshot.coverage&AS_COVERAGE_ENVIRONMENT);
    bool comparable_resources=(previous.snapshot.coverage&AS_COVERAGE_RESOURCES)&&(current.snapshot.coverage&AS_COVERAGE_RESOURCES);
    bool comparable_status=(previous.snapshot.coverage&AS_COVERAGE_STATUS)&&(current.snapshot.coverage&AS_COVERAGE_STATUS);
    if(comparable_environment){credential_entries(previous,before);credential_entries(current,after);}
    if(comparable_resources){resource_entries(previous,before);resource_entries(current,after);}
    if(comparable_status&&previous.snapshot.effective_uid!=current.snapshot.effective_uid){before.emplace("privilege\x1fuid:"+std::to_string(previous.snapshot.effective_uid),ExposureChange{ChangeDirection::granted,"privilege","effective UID "+std::to_string(previous.snapshot.effective_uid),previous.snapshot.effective_uid==0?Severity::critical:Severity::low,previous.snapshot.effective_uid==0});after.emplace("privilege\x1fuid:"+std::to_string(current.snapshot.effective_uid),ExposureChange{ChangeDirection::granted,"privilege","effective UID "+std::to_string(current.snapshot.effective_uid),current.snapshot.effective_uid==0?Severity::critical:Severity::low,current.snapshot.effective_uid==0});}
    std::vector<ExposureChange> changes;
    for(const auto& [key,change]:after)if(!before.count(key)){changes.push_back(change);}
    for(const auto& [key,change]:before)if(!after.count(key)){auto revoked=change;revoked.direction=ChangeDirection::revoked;revoked.attention=false;changes.push_back(std::move(revoked));}
    if(comparable_status){
        uint64_t added=current.snapshot.effective_capabilities&~previous.snapshot.effective_capabilities;
        uint64_t removed=previous.snapshot.effective_capabilities&~current.snapshot.effective_capabilities;
        if(added)changes.push_back(ExposureChange{ChangeDirection::granted,"privilege","Linux capabilities added",Severity::high,true});
        if(removed)changes.push_back(ExposureChange{ChangeDirection::revoked,"privilege","Linux capabilities removed",Severity::low,false});
    }
    uint32_t lost_coverage=previous.snapshot.coverage&~current.snapshot.coverage;
    uint32_t restored_coverage=current.snapshot.coverage&~previous.snapshot.coverage;
    if(lost_coverage)changes.push_back(ExposureChange{ChangeDirection::granted,"observability","Monitoring coverage was lost",Severity::high,true});
    if(restored_coverage)changes.push_back(ExposureChange{ChangeDirection::revoked,"observability","Monitoring coverage was restored",Severity::info,false});
    std::sort(changes.begin(),changes.end(),[](const ExposureChange& x,const ExposureChange& y){if(x.attention!=y.attention)return x.attention>y.attention;if(x.direction!=y.direction)return x.direction==ChangeDirection::granted;if(x.severity!=y.severity)return x.severity>y.severity;return x.identifier<y.identifier;});
    return changes;
}

Policy parse_policy(std::istream& input) {
    Policy policy;std::string text;size_t number=0;bool version_seen=false;std::set<std::string> singleton;
    while(std::getline(input,text)){
        ++number;if(text.size()>4096)throw std::invalid_argument("policy line "+std::to_string(number)+" is too long");
        auto first=text.find_first_not_of(" \t\r");if(first==std::string::npos||text[first]=='#')continue;
        std::istringstream line(text.substr(first));std::string command;line>>command;
        try{
            if(command=="version"){int version=0;if(!(line>>version)||version!=1)throw std::invalid_argument("policy version must be 1");require_end(line);if(version_seen)throw std::invalid_argument("duplicate version");version_seen=true;}
            else if(command=="mode"){std::string value;if(!(line>>value)||(value!="audit"&&value!="enforce"))throw std::invalid_argument("mode must be audit or enforce");require_end(line);if(!singleton.insert(command).second)throw std::invalid_argument("duplicate mode");policy.enforce=value=="enforce";}
            else if(command=="require-full-coverage"||command=="allow-root"||command=="allow-capabilities"){std::string value;if(!(line>>value))throw std::invalid_argument("missing boolean");require_end(line);if(!singleton.insert(command).second)throw std::invalid_argument("duplicate "+command);bool parsed=parse_bool(value);if(command=="require-full-coverage")policy.require_full_coverage=parsed;else if(command=="allow-root")policy.allow_root=parsed;else policy.allow_capabilities=parsed;}
            else if(command=="max-risk-score"){int value=-1;if(!(line>>value)||value<0||value>100)throw std::invalid_argument("max-risk-score must be between 0 and 100");require_end(line);if(!singleton.insert(command).second)throw std::invalid_argument("duplicate max-risk-score");policy.max_risk_score=value;}
            else if(command=="default"){std::string category,value;if(!(line>>category>>value))throw std::invalid_argument("default requires category and action");require_end(line);std::string key=command+":"+category;if(!singleton.insert(key).second)throw std::invalid_argument("duplicate default for "+category);auto action=parse_action(value);if(category=="credential")policy.default_credential=action;else if(category=="sensitive-file")policy.default_sensitive_file=action;else if(category=="network")policy.default_network=action;else throw std::invalid_argument("unsupported default category");}
            else if(command=="credential"||command=="resource-prefix"||command=="network-prefix"||command=="network-endpoint"){std::string pattern,value;if(!(line>>std::quoted(pattern)>>value))throw std::invalid_argument("rule requires pattern and action");require_end(line);if(command=="credential"&&!valid_credential_name(pattern))throw std::invalid_argument("invalid credential name");if(command=="resource-prefix"&&(pattern.empty()||pattern[0]!='/'))throw std::invalid_argument("resource prefix must be absolute");bool network=command=="network-prefix"||command=="network-endpoint";if(network&&(pattern.rfind("tcp://",0)!=0&&pattern.rfind("tcp6://",0)!=0&&pattern.rfind("udp://",0)!=0&&pattern.rfind("udp6://",0)!=0))throw std::invalid_argument("network rule must start with tcp://, tcp6://, udp://, or udp6://");std::string category=command=="credential"?"credential":command=="resource-prefix"?"filesystem":"network";for(const auto& rule:policy.rules)if(rule.category==category&&rule.pattern==pattern)throw std::invalid_argument("duplicate policy rule");policy.rules.push_back({category,std::move(pattern),parse_action(value),command=="resource-prefix"||command=="network-prefix"});}
            else throw std::invalid_argument("unknown policy directive: "+command);
        }catch(const std::invalid_argument& error){throw std::invalid_argument("policy line "+std::to_string(number)+": "+error.what());}
    }
    if(!version_seen)throw std::invalid_argument("policy version is required");
    return policy;
}

PolicyEvaluation evaluate_policy(const Assessment& assessment,const Policy& policy,const std::set<std::string>& approvals){
    PolicyEvaluation evaluation;const auto& snapshot=assessment.snapshot;
    constexpr uint32_t full=AS_COVERAGE_STATUS|AS_COVERAGE_ENVIRONMENT|AS_COVERAGE_RESOURCES;
    if(policy.require_full_coverage&&(snapshot.coverage&full)!=full)add_policy_decision(evaluation,PolicyAction::deny,"observability","full-coverage","Required monitoring coverage is unavailable",policy,approvals);
    if((snapshot.coverage&AS_COVERAGE_STATUS)&&!policy.allow_root&&snapshot.effective_uid==0)add_policy_decision(evaluation,PolicyAction::deny,"privilege","root","Root execution is forbidden",policy,approvals);
    if((snapshot.coverage&AS_COVERAGE_STATUS)&&!policy.allow_capabilities&&snapshot.effective_capabilities)add_policy_decision(evaluation,PolicyAction::deny,"privilege","capabilities","Linux capabilities are forbidden",policy,approvals);
    if(assessment.risk_score>policy.max_risk_score)add_policy_decision(evaluation,PolicyAction::deny,"risk","score","Risk score exceeds policy maximum",policy,approvals);
    if(snapshot.coverage&AS_COVERAGE_ENVIRONMENT)for(size_t i=0;i<snapshot.credential_count;++i){const auto& c=snapshot.credentials[i];auto action=rule_action(policy,"credential",c.name,policy.default_credential);add_policy_decision(evaluation,action,"credential",c.name,"Credential exposure requires a policy decision",policy,approvals);}
    if(snapshot.coverage&AS_COVERAGE_RESOURCES)for(size_t i=0;i<snapshot.resource_count;++i){const auto& r=snapshot.resources[i];std::string category=r.kind==AS_RESOURCE_SOCKET?"network":"filesystem";auto fallback=r.kind==AS_RESOURCE_SOCKET?policy.default_network:policy.default_sensitive_file;auto action=rule_action(policy,category,r.path,fallback);add_policy_decision(evaluation,action,category,r.path,"Resource exposure requires a policy decision",policy,approvals);}
    return evaluation;
}

std::string private_credential(const as_credential& credential, Privacy privacy) {
    return privacy == Privacy::strict ? "[credential name redacted]" : credential.name;
}
std::string private_resource(const as_resource& resource, Privacy privacy) {
    return privacy == Privacy::strict ? "[resource identifier redacted]" : resource.path;
}

std::string to_json(const Assessment& a, long long timestamp_ms, Privacy privacy, const std::vector<ExposureChange>& changes,const PolicyEvaluation* policy) {
    std::ostringstream o;
    std::string executable=privacy==Privacy::strict?"[executable path redacted]":a.snapshot.executable;
    std::string working_directory=privacy==Privacy::strict?"[working directory redacted]":a.snapshot.working_directory;
    std::string process_name=privacy==Privacy::strict?"[process name redacted]":a.snapshot.process_name;
    std::string cgroup=privacy==Privacy::strict?"[cgroup path redacted]":a.snapshot.cgroup_path;
    o << "{\"schema\":\"io.agentshield.snapshot/v1\",\"timestampMs\":"<<timestamp_ms<<",\"coverage\":"<<a.snapshot.coverage<<",\"process\":{\"pid\":"<<a.snapshot.pid<<",\"parentPid\":"<<a.snapshot.parent_pid<<",\"name\":\""<<escape(process_name)<<"\",\"executable\":\""<<escape(executable)<<"\",\"workingDirectory\":\""<<escape(working_directory)<<"\",\"cgroup\":\""<<escape(cgroup)<<"\",\"effectiveUid\":"<<a.snapshot.effective_uid<<",\"effectiveCapabilities\":\""<<std::hex<<a.snapshot.effective_capabilities<<std::dec<<"\"},\"risk\":{\"score\":"<<a.risk_score<<",\"level\":\""<<severity_name(a.level)<<"\"},\"credentials\":[";
    for(size_t i=0;i<a.snapshot.credential_count;++i){if(i)o<<',';const auto& c=a.snapshot.credentials[i];o<<"{\"name\":\""<<escape(private_credential(c,privacy))<<"\",\"severity\":\""<<severity_name(severity_from(c.risk))<<"\"}";}
    o << "],\"resources\":[";
    for(size_t i=0;i<a.snapshot.resource_count;++i){if(i)o<<',';const auto& r=a.snapshot.resources[i];o<<"{\"kind\":\""<<as_resource_kind_name(r.kind)<<"\",\"identifier\":\""<<escape(private_resource(r,privacy))<<"\",\"severity\":\""<<severity_name(severity_from(r.risk))<<"\",\"network\":{";if(r.kind==AS_RESOURCE_SOCKET&&privacy!=Privacy::strict)o<<"\"attributed\":"<<(r.network_protocol[0]?"true":"false")<<",\"protocol\":\""<<escape(r.network_protocol)<<"\",\"localEndpoint\":\""<<escape(r.local_endpoint)<<"\",\"remoteEndpoint\":\""<<escape(r.remote_endpoint)<<"\",\"state\":\""<<escape(r.connection_state)<<"\"";else o<<"\"attributed\":false";o<<"}}";}
    o << "],\"findings\":[";
    for(size_t i=0;i<a.findings.size();++i){if(i)o<<',';const auto& f=a.findings[i];std::string evidence=privacy==Privacy::strict&&f.category=="credential"?"[credential name redacted]":privacy==Privacy::strict&&(f.category=="filesystem"||f.category=="network")?"[resource identifier redacted]":f.evidence;o<<"{\"ruleId\":\""<<f.rule_id<<"\",\"category\":\""<<f.category<<"\",\"severity\":\""<<severity_name(f.severity)<<"\",\"score\":"<<f.score<<",\"title\":\""<<escape(f.title)<<"\",\"evidence\":\""<<escape(evidence)<<"\",\"recommendation\":\""<<escape(f.recommendation)<<"\"}";}
    o << "],\"changes\":[";
    for(size_t i=0;i<changes.size();++i){if(i)o<<',';const auto& c=changes[i];o<<"{\"direction\":\""<<direction_name(c.direction)<<"\",\"category\":\""<<escape(c.category)<<"\",\"severity\":\""<<severity_name(c.severity)<<"\",\"attention\":"<<(c.attention?"true":"false")<<",\"identifier\":\""<<escape(private_change_identifier(c,privacy))<<"\"}";}
    o << "],\"policy\":{";
    o << "\"evaluated\":"<<(policy?"true":"false")<<",\"blocked\":"<<(policy&&policy->blocked?"true":"false")<<",\"decisions\":[";
    if(policy)for(size_t i=0;i<policy->decisions.size();++i){if(i)o<<',';const auto& d=policy->decisions[i];o<<"{\"action\":\""<<action_name(d.action)<<"\",\"category\":\""<<escape(d.category)<<"\",\"identifier\":\""<<escape(private_policy_identifier(d,privacy))<<"\",\"reason\":\""<<escape(d.reason)<<"\",\"approved\":"<<(d.approved?"true":"false")<<",\"blocking\":"<<(d.blocking?"true":"false")<<"}";}
    o << "]}}\n"; return o.str();
}

std::string to_tsv(const Assessment& a,long long timestamp_ms,Privacy privacy,const std::vector<ExposureChange>& changes,const PolicyEvaluation* policy) {
    std::string executable=privacy==Privacy::strict?"[executable path redacted]":a.snapshot.executable;
    std::string process_name=privacy==Privacy::strict?"[process name redacted]":a.snapshot.process_name;
    std::string cgroup=privacy==Privacy::strict?"[cgroup path redacted]":a.snapshot.cgroup_path;
    std::ostringstream o;o<<"SNAPSHOT\t"<<timestamp_ms<<'\t'<<a.snapshot.pid<<'\t'<<a.risk_score<<'\t'<<severity_name(a.level)<<'\t'<<tsv_field(process_name)<<'\t'<<a.snapshot.effective_uid<<'\t'<<std::hex<<a.snapshot.effective_capabilities<<std::dec<<'\t'<<tsv_field(executable)<<'\t'<<tsv_field(cgroup)<<'\n';
    for(size_t i=0;i<a.snapshot.credential_count;++i){const auto& c=a.snapshot.credentials[i];o<<"CREDENTIAL\t"<<severity_name(severity_from(c.risk))<<'\t'<<tsv_field(private_credential(c,privacy))<<"\tEnvironment variable name only; value was not retained or emitted\n";}
    for(size_t i=0;i<a.snapshot.resource_count;++i){const auto& r=a.snapshot.resources[i];bool visible=r.kind==AS_RESOURCE_SOCKET&&privacy!=Privacy::strict;o<<"RESOURCE\t"<<severity_name(severity_from(r.risk))<<'\t'<<as_resource_kind_name(r.kind)<<'\t'<<tsv_field(private_resource(r,privacy))<<'\t'<<(visible?tsv_field(r.network_protocol):"")<<'\t'<<(visible?tsv_field(r.local_endpoint):"")<<'\t'<<(visible?tsv_field(r.remote_endpoint):"")<<'\t'<<(visible?tsv_field(r.connection_state):"")<<'\n';}
    for(const auto& f:a.findings){std::string evidence=privacy==Privacy::strict&&f.category=="credential"?"[credential name redacted]":privacy==Privacy::strict&&(f.category=="filesystem"||f.category=="network")?"[resource identifier redacted]":f.evidence;o<<"FINDING\t"<<severity_name(f.severity)<<'\t'<<tsv_field(f.rule_id)<<'\t'<<tsv_field(f.title)<<'\t'<<tsv_field(evidence)<<'\t'<<tsv_field(f.recommendation)<<'\n';}
    for(const auto& c:changes)o<<"CHANGE\t"<<timestamp_ms<<'\t'<<direction_name(c.direction)<<'\t'<<severity_name(c.severity)<<'\t'<<tsv_field(c.category)<<'\t'<<tsv_field(private_change_identifier(c,privacy))<<'\t'<<(c.attention?"ATTENTION":"NORMAL")<<'\n';
    if(policy)for(const auto& d:policy->decisions)o<<"POLICY\t"<<action_name(d.action)<<'\t'<<tsv_field(d.category)<<'\t'<<tsv_field(private_policy_identifier(d,privacy))<<'\t'<<tsv_field(d.reason)<<'\t'<<(d.approved?"APPROVED":d.blocking?"BLOCKING":"ATTENTION")<<'\n';
    o<<"END\n";return o.str();
}
}
