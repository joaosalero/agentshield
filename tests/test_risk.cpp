#include "risk_engine.hpp"
#include <cassert>
#include <cstring>
#include <iostream>
int main(){as_snapshot s{};s.pid=42;s.effective_uid=1000;std::strcpy(s.process_name,"test-agent");s.credential_count=1;std::strcpy(s.credentials[0].name,"SYNTHETIC_DEMO_TOKEN_NAME");s.credentials[0].risk=3;s.resource_count=1;std::strcpy(s.resources[0].path,"/tmp/file\tFINDING\tforged");s.resources[0].kind=AS_RESOURCE_SENSITIVE_FILE;s.resources[0].risk=3;auto a=agentshield::assess(s);assert(a.risk_score==40);assert(a.level==agentshield::Severity::high);assert(a.findings.size()==2);auto json=agentshield::to_json(a,1);assert(json.find("SYNTHETIC_DEMO_TOKEN_NAME")!=std::string::npos);auto tsv=agentshield::to_tsv(a,1);assert(tsv.find("CREDENTIAL\tHIGH\tSYNTHETIC_DEMO_TOKEN_NAME")!=std::string::npos);assert(tsv.find("\tFINDING\tforged")==std::string::npos);std::cout<<"risk engine: OK\n";}
