#include "agentshield/sensor.h"
#include "audit_log.hpp"
#include "risk_engine.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <optional>
#include <openssl/crypto.h>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <fstream>
#include <iterator>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#ifndef AGENTSHIELD_VERSION
#define AGENTSHIELD_VERSION "0.0.0-dev"
#endif

namespace {
volatile std::sig_atomic_t running=1;
int audit_fd=-1;
std::optional<agentshield::AuditKey> audit_key;
std::uint64_t audit_sequence=0;
std::string audit_previous_mac(64,'0');
std::uint64_t audit_size=0;
std::uint64_t audit_max_bytes=64U*1024U*1024U;
struct CgroupScope { std::string parent,monitor,agent,disable_controllers; bool active=false; } cgroup_scope;
struct RunLimits { int memory_mb=0; int cpu_seconds=0; int processes=0; int cpu_percent=0; bool no_new_privileges=true; bool inherit_output=false; bool inherit_input=false; bool cgroup=false; };
void stop(int){running=0;}
long long now_ms(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();}

void usage(){
    std::cout << "AgentShield - runtime security monitor for AI agents\n\nUsage:\n"
      "  agentshield inspect PID [OPTIONS]\n  agentshield watch PID [OPTIONS]\n"
      "  agentshield run [OPTIONS] -- COMMAND [ARGS...]\n"
      "  agentshield audit init-key FILE\n"
      "  agentshield audit verify FILE --audit-key FILE\n"
      "  agentshield audit export FILE --audit-key FILE\n"
      "  agentshield --version\n\nOptions:\n"
      "  --format json|tsv          Output format (default: json)\n"
      "  --privacy standard|strict Strict redacts credential names and paths\n"
      "  --interval MS              Watch interval (default: 1000)\n"
      "  --audit FILE               Append authenticated audit envelopes\n"
      "  --audit-key FILE           Owner-only 32-byte HMAC key file\n"
      "  --audit-max-bytes N        Fail closed at this audit size (default: 64 MiB)\n"
      "  --policy FILE              Evaluate a secure AgentShield policy file\n"
      "  --approve CATEGORY:VALUE   Approve one policy-gated exposure for this run\n"
      "  --max-memory-mb N          Supervised process address-space limit\n"
      "  --max-cpu-seconds N        Supervised process CPU limit\n"
      "  --max-processes N          Supervised process count limit\n"
      "  --cgroup                   Put the complete process tree in a delegated cgroup v2\n"
      "  --max-cpu-percent N        Cgroup CPU quota from 1 to 1000 percent\n"
      "  --agent-output MODE        discard (default) or inherit to stderr\n"
      "  --agent-input MODE         discard (default) or inherit\n"
      "  --allow-new-privs          Disable the default no_new_privs control\n\n"
      "Credential values and command arguments are never retained in snapshots or emitted.\n";
}

int parse_positive(const std::string& value){
    try{size_t used=0;int n=std::stoi(value,&used);if(n>0&&used==value.size())return n;}catch(...){ }
    throw std::invalid_argument("expected a positive integer");
}
std::uint64_t parse_positive_size(const std::string& value){try{size_t used=0;unsigned long long n=std::stoull(value,&used);if(n>0&&used==value.size())return n;}catch(...){ }throw std::invalid_argument("expected a positive integer");}
void write_all(int fd,const std::string& data){
    size_t offset=0;while(offset<data.size()){ssize_t count=write(fd,data.data()+offset,data.size()-offset);if(count<0&&errno==EINTR)continue;if(count<=0)throw std::runtime_error("secure audit write failed");offset+=static_cast<size_t>(count);}
}
void write_control(const std::string& path,const std::string& value){int fd=open(path.c_str(),O_WRONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)throw std::runtime_error("cannot open cgroup control "+path+": "+std::strerror(errno));std::size_t offset=0;while(offset<value.size()){ssize_t count=write(fd,value.data()+offset,value.size()-offset);if(count<0&&errno==EINTR)continue;if(count<=0){int saved=errno;close(fd);throw std::runtime_error("cannot write cgroup control "+path+": "+std::strerror(saved));}offset+=static_cast<std::size_t>(count);}close(fd);}
bool cgroup_populated(const std::string& path){std::ifstream input(path+"/cgroup.events");std::string name;int value=0;while(input>>name>>value)if(name=="populated")return value!=0;return false;}
std::string current_cgroup_path(){std::ifstream input("/proc/self/cgroup");std::string line;while(std::getline(input,line)){if(line.rfind("0::/",0)==0){std::string relative=line.substr(3);if(relative.find("..")!=std::string::npos||relative.find_first_of("\r\n")!=std::string::npos)break;return "/sys/fs/cgroup"+relative;}}throw std::runtime_error("unified cgroup v2 membership is unavailable");}
void cleanup_cgroup(bool strict=false){if(!cgroup_scope.active)return;std::string issue;try{std::string kill_path=cgroup_scope.agent+"/cgroup.kill";if(access(kill_path.c_str(),W_OK)==0)write_control(kill_path,"1\n");}catch(const std::exception& error){issue=error.what();}for(int attempt=0;attempt<100&&cgroup_populated(cgroup_scope.agent);++attempt)std::this_thread::sleep_for(std::chrono::milliseconds(10));if(rmdir(cgroup_scope.agent.c_str())!=0&&errno!=ENOENT&&issue.empty())issue="cannot remove agent cgroup: "+std::string(std::strerror(errno));if(!cgroup_scope.disable_controllers.empty()){try{write_control(cgroup_scope.parent+"/cgroup.subtree_control",cgroup_scope.disable_controllers+"\n");}catch(const std::exception& error){if(issue.empty())issue=error.what();}}try{write_control(cgroup_scope.parent+"/cgroup.procs",std::to_string(getpid())+"\n");}catch(const std::exception& error){if(issue.empty())issue=error.what();}if(rmdir(cgroup_scope.monitor.c_str())!=0&&errno!=ENOENT&&issue.empty())issue="cannot remove monitor cgroup: "+std::string(std::strerror(errno));cgroup_scope={};if(strict&&!issue.empty())throw std::runtime_error("cgroup cleanup verification failed: "+issue);}
void prepare_cgroup(const RunLimits& limits){
    cgroup_scope.parent=current_cgroup_path();std::string suffix=std::to_string(getpid());cgroup_scope.monitor=cgroup_scope.parent+"/agentshield-monitor-"+suffix;cgroup_scope.agent=cgroup_scope.parent+"/agentshield-agent-"+suffix;
    if(access((cgroup_scope.parent+"/cgroup.controllers").c_str(),R_OK)!=0||access(cgroup_scope.parent.c_str(),W_OK)!=0)throw std::runtime_error("--cgroup requires a writable delegated cgroup v2 scope; launch AgentShield through a trusted service manager with delegation");
    if(mkdir(cgroup_scope.monitor.c_str(),0700)!=0)throw std::runtime_error("cannot create monitor cgroup: "+std::string(std::strerror(errno)));
    cgroup_scope.active=true;
    try{
        write_control(cgroup_scope.monitor+"/cgroup.procs",std::to_string(getpid())+"\n");
        std::ifstream enabled_input(cgroup_scope.parent+"/cgroup.subtree_control");std::string enabled((std::istreambuf_iterator<char>(enabled_input)),std::istreambuf_iterator<char>());auto missing=[&](const std::string& name){std::istringstream words(enabled);std::string word;while(words>>word)if(word==name)return false;return true;};std::string controllers;if(limits.memory_mb&&missing("memory")){controllers+="+memory ";cgroup_scope.disable_controllers+="-memory ";}if(limits.processes&&missing("pids")){controllers+="+pids ";cgroup_scope.disable_controllers+="-pids ";}if(limits.cpu_percent&&missing("cpu")){controllers+="+cpu ";cgroup_scope.disable_controllers+="-cpu ";}if(!controllers.empty())write_control(cgroup_scope.parent+"/cgroup.subtree_control",controllers+"\n");
        if(mkdir(cgroup_scope.agent.c_str(),0700)!=0)throw std::runtime_error("cannot create agent cgroup: "+std::string(std::strerror(errno)));
        if(limits.memory_mb)write_control(cgroup_scope.agent+"/memory.max",std::to_string(static_cast<unsigned long long>(limits.memory_mb)*1024U*1024U)+"\n");
        if(limits.processes)write_control(cgroup_scope.agent+"/pids.max",std::to_string(limits.processes)+"\n");
        if(limits.cpu_percent)write_control(cgroup_scope.agent+"/cpu.max",std::to_string(static_cast<unsigned long long>(limits.cpu_percent)*1000U)+" 100000\n");
        if(access((cgroup_scope.agent+"/memory.oom.group").c_str(),W_OK)==0)write_control(cgroup_scope.agent+"/memory.oom.group","1\n");
    }catch(...){cleanup_cgroup();throw;}
}
void attach_cgroup(pid_t pid){if(cgroup_scope.active)write_control(cgroup_scope.agent+"/cgroup.procs",std::to_string(pid)+"\n");}
void finalize_audit(){if(audit_fd<0)return;if(fsync(audit_fd)!=0)throw std::runtime_error("audit synchronization failed");close(audit_fd);audit_fd=-1;if(audit_key){OPENSSL_cleanse(audit_key->data(),audit_key->size());audit_key.reset();}}
std::string read_secure_file(const std::string& path,std::size_t maximum,const char* purpose,bool root_allowed,bool owner_only=false){
    int fd=open(path.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    if(fd<0)throw std::runtime_error(std::string("cannot open ")+purpose+" safely: "+std::strerror(errno));
    struct stat status{};
    if(fstat(fd,&status)!=0){close(fd);throw std::runtime_error(std::string("cannot inspect ")+purpose+" safely");}
    bool owner_ok=status.st_uid==geteuid()||(root_allowed&&status.st_uid==0);
    if(!S_ISREG(status.st_mode)||!owner_ok||(owner_only?(status.st_mode&0077)!=0:(status.st_mode&0022)!=0)||status.st_size<0||static_cast<std::uint64_t>(status.st_size)>maximum){close(fd);throw std::runtime_error(std::string(purpose)+" must be a regular file with trusted ownership, secure permissions, and bounded size");}
    std::string data;data.reserve(static_cast<std::size_t>(status.st_size));char buffer[4096];
    for(;;){ssize_t count=read(fd,buffer,sizeof buffer);if(count<0&&errno==EINTR)continue;if(count<0){close(fd);throw std::runtime_error(std::string("cannot read ")+purpose+" safely");}if(count==0)break;if(data.size()+static_cast<std::size_t>(count)>maximum){close(fd);throw std::runtime_error(std::string(purpose)+" exceeds its size limit");}data.append(buffer,static_cast<std::size_t>(count));}
    close(fd);return data;
}
agentshield::AuditKey read_audit_key(const std::string& path){
    int fd=open(path.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);if(fd<0)throw std::runtime_error("cannot open audit key safely: "+std::string(std::strerror(errno)));
    struct stat status{};if(fstat(fd,&status)!=0||!S_ISREG(status.st_mode)||status.st_uid!=geteuid()||(status.st_mode&0077)!=0||status.st_size<64||status.st_size>66){close(fd);throw std::runtime_error("audit key must be an owner-only regular file owned by the current user");}
    std::string data;char buffer[66];for(;;){ssize_t count=read(fd,buffer,sizeof buffer);if(count<0&&errno==EINTR)continue;if(count<0){close(fd);throw std::runtime_error("cannot read audit key safely");}if(count==0)break;if(data.size()+static_cast<std::size_t>(count)>66){close(fd);throw std::runtime_error("audit key is oversized");}data.append(buffer,static_cast<std::size_t>(count));}close(fd);try{auto key=agentshield::audit_key_from_hex(data);OPENSSL_cleanse(data.data(),data.size());return key;}catch(...){OPENSSL_cleanse(data.data(),data.size());throw;}
}
void create_audit_key(const std::string& path){
    agentshield::AuditKey key{};std::size_t offset=0;while(offset<key.size()){ssize_t count=syscall(SYS_getrandom,key.data()+offset,key.size()-offset,0);if(count<0&&errno==EINTR)continue;if(count<=0)throw std::runtime_error("secure random generation failed");offset+=static_cast<std::size_t>(count);}
    int fd=open(path.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);if(fd<0)throw std::runtime_error("cannot create audit key safely: "+std::string(std::strerror(errno)));
    std::string encoded=agentshield::audit_key_to_hex(key)+"\n";try{write_all(fd,encoded);if(fsync(fd)!=0)throw std::runtime_error("audit key synchronization failed");close(fd);OPENSSL_cleanse(encoded.data(),encoded.size());OPENSSL_cleanse(key.data(),key.size());}catch(...){close(fd);unlink(path.c_str());OPENSSL_cleanse(encoded.data(),encoded.size());OPENSSL_cleanse(key.data(),key.size());throw;}
}
int open_audit(const std::string& path,const agentshield::AuditKey& key,std::uint64_t maximum){
    int fd=open(path.c_str(),O_RDWR|O_APPEND|O_CREAT|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK,0600);
    if(fd<0)throw std::runtime_error("cannot open audit file safely: "+std::string(std::strerror(errno)));
    struct stat status{};
    if(fstat(fd,&status)!=0||!S_ISREG(status.st_mode)||status.st_uid!=geteuid()||(status.st_mode&0077)!=0||status.st_size<0||static_cast<std::uint64_t>(status.st_size)>maximum){close(fd);throw std::runtime_error("audit file must be a regular, owner-only file owned by the current user and within the configured size limit");}
    if(flock(fd,LOCK_EX|LOCK_NB)!=0){close(fd);throw std::runtime_error("audit file is already in use by another writer");}
    int flags=fcntl(fd,F_GETFL);
    if(flags<0||fcntl(fd,F_SETFL,flags&~O_NONBLOCK)!=0){close(fd);throw std::runtime_error("cannot configure audit file safely");}
    std::string existing;existing.reserve(static_cast<std::size_t>(status.st_size));if(lseek(fd,0,SEEK_SET)<0){close(fd);throw std::runtime_error("cannot inspect existing audit chain");}char buffer[4096];for(;;){ssize_t count=read(fd,buffer,sizeof buffer);if(count<0&&errno==EINTR)continue;if(count<0){close(fd);throw std::runtime_error("cannot inspect existing audit chain");}if(count==0)break;existing.append(buffer,static_cast<std::size_t>(count));}
    std::istringstream input(existing);auto verified=agentshield::verify_audit_stream(input,key);audit_sequence=verified.records;audit_previous_mac=verified.final_mac;audit_size=static_cast<std::uint64_t>(status.st_size);audit_max_bytes=maximum;
    return fd;
}
std::string read_policy_file(const std::string& path){
    return read_secure_file(path,65536,"policy file",true);
}
void validate_approval(const std::string& approval){
    auto separator=approval.find(':');if(separator==std::string::npos||separator==0||separator+1>=approval.size()||approval.find_first_of("\r\n\t")!=std::string::npos)throw std::invalid_argument("approval must be CATEGORY:VALUE");
    std::string category=approval.substr(0,separator);if(category!="credential"&&category!="filesystem"&&category!="network")throw std::invalid_argument("approval category must be credential, filesystem, or network");
}
int emit(int pid,const std::string& format,agentshield::Privacy privacy,agentshield::Assessment* previous=nullptr,const agentshield::Policy* policy=nullptr,const std::set<std::string>& approvals={}){
    as_snapshot snapshot{};char error[256];if(as_collect_snapshot(pid,&snapshot,error,sizeof error)!=0){std::cerr<<"agentshield: "<<error<<'\n';return 1;}
    auto assessment=agentshield::assess(snapshot);auto changes=previous&&previous->snapshot.pid?agentshield::detect_changes(*previous,assessment):std::vector<agentshield::ExposureChange>{};std::optional<agentshield::PolicyEvaluation> evaluation;if(policy)evaluation=agentshield::evaluate_policy(assessment,*policy,approvals);long long timestamp=now_ms();auto evaluated=evaluation?&*evaluation:nullptr;std::string json=agentshield::to_json(assessment,timestamp,privacy,changes,evaluated);std::cout<<(format=="tsv"?agentshield::to_tsv(assessment,timestamp,privacy,changes,evaluated):json)<<std::flush;
    if(audit_fd>=0){try{agentshield::AuditRecord record{audit_sequence+1,timestamp,audit_previous_mac,"",json,""};std::string encoded=agentshield::encode_audit_record(record,*audit_key);if(encoded.size()>audit_max_bytes-audit_size)throw std::runtime_error("audit retention limit reached; archive or replace the verified log explicitly");write_all(audit_fd,encoded);audit_size+=encoded.size();audit_sequence++;audit_previous_mac=agentshield::decode_audit_record(encoded.substr(0,encoded.size()-1)).mac;}catch(const std::exception& error){std::cerr<<"agentshield: "<<error.what()<<'\n';return 1;}}
    if(previous)*previous=std::move(assessment);
    return evaluation&&evaluation->blocked?3:0;
}
void set_limit(int resource,rlim_t value,const char* description){struct rlimit limit{value,value};if(setrlimit(resource,&limit)!=0){std::cerr<<"agentshield: cannot apply "<<description<<"\n";_exit(126);}}
void close_inherited_descriptors(int preserve){
#ifdef SYS_close_range
    bool lower=preserve<=3||syscall(SYS_close_range,3U,static_cast<unsigned>(preserve-1),0U)==0;
    bool upper=syscall(SYS_close_range,static_cast<unsigned>(preserve+1),~0U,0U)==0;
    if(lower&&upper)return;
#endif
    long maximum=sysconf(_SC_OPEN_MAX);if(maximum<0||maximum>65536)maximum=65536;for(int fd=3;fd<maximum;++fd)if(fd!=preserve)close(fd);
}
void harden_child(const RunLimits& limits,int status_fd,bool gate_before_exec){
    if(setpgid(0,0)!=0)_exit(126);
    if(prctl(PR_SET_PDEATHSIG,SIGTERM)!=0)_exit(126);
    if(getppid()==1)_exit(126);
    set_limit(RLIMIT_CORE,0,"core-dump protection");
    if(limits.no_new_privileges&&prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)!=0)_exit(126);
    if(limits.memory_mb)set_limit(RLIMIT_AS,static_cast<rlim_t>(limits.memory_mb)*1024U*1024U,"memory limit");
    if(limits.cpu_seconds)set_limit(RLIMIT_CPU,static_cast<rlim_t>(limits.cpu_seconds),"CPU limit");
    if(limits.processes)set_limit(RLIMIT_NPROC,static_cast<rlim_t>(limits.processes),"process limit");
    int null_fd=open("/dev/null",O_RDWR|O_CLOEXEC);
    if(null_fd<0)_exit(126);
    if(!limits.inherit_input&&dup2(null_fd,STDIN_FILENO)<0)_exit(126);
    if(limits.inherit_output){
        if(dup2(STDERR_FILENO,STDOUT_FILENO)<0)_exit(126);
    }else{
        if(dup2(null_fd,STDOUT_FILENO)<0||dup2(null_fd,STDERR_FILENO)<0)_exit(126);
    }
    if(null_fd>STDERR_FILENO)close(null_fd);
    close_inherited_descriptors(status_fd);
    if(gate_before_exec){if(ptrace(PTRACE_TRACEME,0,nullptr,nullptr)!=0)_exit(126);if(raise(SIGSTOP)!=0)_exit(126);}
}
int exit_result(int status){return WIFEXITED(status)?WEXITSTATUS(status):WIFSIGNALED(status)?128+WTERMSIG(status):1;}
void harden_monitor(){
    struct rlimit limit{0,0};
    if(setrlimit(RLIMIT_CORE,&limit)!=0||prctl(PR_SET_DUMPABLE,0)!=0)throw std::runtime_error("cannot disable monitor memory dumps");
}
void terminate_group(pid_t group){
    if(group<=0)return;
    bool group_gone=false;
    if(kill(-group,SIGTERM)!=0&&errno==ESRCH)group_gone=true;
    for(int attempt=0;attempt<20;++attempt){
        if(group_gone||(kill(-group,0)!=0&&errno==ESRCH)){group_gone=true;break;}
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    if(!group_gone&&kill(-group,SIGKILL)!=0&&errno!=ESRCH)std::cerr<<"agentshield: warning: process-group kill failed\n";
    if(cgroup_scope.active){try{std::string path=cgroup_scope.agent+"/cgroup.kill";if(access(path.c_str(),W_OK)==0)write_control(path,"1\n");}catch(...){std::cerr<<"agentshield: warning: cgroup kill failed\n";}}
}
}

int main(int argc,char** argv){
    try{
        harden_monitor();
        if(argc<2||std::string(argv[1])=="--help"){usage();return argc<2?2:0;}
        if(std::string(argv[1])=="--version"){if(argc!=2)throw std::invalid_argument("--version accepts no arguments");std::cout<<"AgentShield "<<AGENTSHIELD_VERSION<<'\n';return 0;}
        std::string action=argv[1],format="json",privacy_text="standard",audit_path,audit_key_path,policy_path;std::set<std::string> approvals;int interval=1000,pid=0,command_index=-1;std::uint64_t configured_audit_max=64U*1024U*1024U;bool audit_max_configured=false;RunLimits limits;
        if(action=="audit"){
            if(argc<4)throw std::invalid_argument("audit requires init-key, verify, or export and a file");
            std::string operation=argv[2],path=argv[3];
            if(operation=="init-key"){if(argc!=4)throw std::invalid_argument("audit init-key accepts exactly one file");create_audit_key(path);std::cout<<"Audit key created securely.\n";return 0;}
            if(operation!="verify"&&operation!="export")throw std::invalid_argument("unknown audit operation: "+operation);
            for(int j=4;j<argc;++j){std::string argument=argv[j];if(argument=="--audit-key"&&j+1<argc)audit_key_path=argv[++j];else throw std::invalid_argument("unknown or incomplete audit option: "+argument);}if(audit_key_path.empty())throw std::invalid_argument("audit verify/export requires --audit-key");auto key=read_audit_key(audit_key_path);std::string data=read_secure_file(path,256U*1024U*1024U,"audit file",false,true);std::istringstream input(data);std::vector<agentshield::AuditRecord> records;auto result=agentshield::verify_audit_stream(input,key,operation=="export"?&records:nullptr);
            if(result.records==0)throw std::invalid_argument("audit log contains no records");
            if(operation=="verify"){std::cout<<"{\"schema\":\"io.agentshield.audit-verification/v1\",\"verified\":true,\"records\":"<<result.records<<",\"finalMac\":\""<<result.final_mac<<"\"}\n";return 0;}
            for(const auto& record:records)std::cout<<agentshield::helix_export_json(record);
            return 0;
        }
        int i=2;if(action=="inspect"||action=="watch"){if(i>=argc)throw std::invalid_argument("PID is required");pid=parse_positive(argv[i++]);}
        for(;i<argc;++i){std::string argument=argv[i];if(argument=="--"){command_index=i+1;break;}if(argument=="--allow-new-privs"){limits.no_new_privileges=false;continue;}if(argument=="--cgroup"){limits.cgroup=true;continue;}
            if((argument=="--interval"||argument=="--format"||argument=="--privacy"||argument=="--audit"||argument=="--audit-key"||argument=="--audit-max-bytes"||argument=="--policy"||argument=="--approve"||argument=="--max-memory-mb"||argument=="--max-cpu-seconds"||argument=="--max-processes"||argument=="--max-cpu-percent"||argument=="--agent-output"||argument=="--agent-input")&&i+1<argc){std::string value=argv[++i];if(argument=="--interval")interval=parse_positive(value);else if(argument=="--format")format=value;else if(argument=="--privacy")privacy_text=value;else if(argument=="--audit")audit_path=value;else if(argument=="--audit-key")audit_key_path=value;else if(argument=="--audit-max-bytes"){configured_audit_max=parse_positive_size(value);audit_max_configured=true;}else if(argument=="--policy")policy_path=value;else if(argument=="--approve"){validate_approval(value);approvals.insert(value);}else if(argument=="--max-memory-mb")limits.memory_mb=parse_positive(value);else if(argument=="--max-cpu-seconds")limits.cpu_seconds=parse_positive(value);else if(argument=="--max-processes")limits.processes=parse_positive(value);else if(argument=="--max-cpu-percent"){limits.cpu_percent=parse_positive(value);if(limits.cpu_percent>1000)throw std::invalid_argument("max CPU percent cannot exceed 1000");}else if(argument=="--agent-output"){if(value=="inherit")limits.inherit_output=true;else if(value!="discard")throw std::invalid_argument("agent output must be discard or inherit");}else{if(value=="inherit")limits.inherit_input=true;else if(value!="discard")throw std::invalid_argument("agent input must be discard or inherit");}continue;}throw std::invalid_argument("unknown or incomplete option: "+argument);}
        if(format!="json"&&format!="tsv")throw std::invalid_argument("format must be json or tsv");
        if(privacy_text!="standard"&&privacy_text!="strict")throw std::invalid_argument("privacy must be standard or strict");
        if(action!="inspect"&&action!="watch"&&action!="run")throw std::invalid_argument("unknown action: "+action);
        if(action!="run"&&(limits.memory_mb||limits.cpu_seconds||limits.processes||limits.cpu_percent||limits.cgroup||!limits.no_new_privileges||limits.inherit_output||limits.inherit_input))throw std::invalid_argument("process controls are valid only with run");
        if(limits.cpu_percent&&!limits.cgroup)throw std::invalid_argument("--max-cpu-percent requires --cgroup");
        if(!approvals.empty()&&policy_path.empty())throw std::invalid_argument("--approve requires --policy");
        if(audit_path.empty()!=audit_key_path.empty())throw std::invalid_argument("--audit and --audit-key must be provided together");
        if(audit_path.empty()&&audit_max_configured)throw std::invalid_argument("--audit-max-bytes requires --audit");
        if(configured_audit_max>256U*1024U*1024U)throw std::invalid_argument("--audit-max-bytes cannot exceed 256 MiB per session file");
        if(action!="run"&&!approvals.empty())throw std::invalid_argument("approvals are valid only with run");
        std::optional<agentshield::Policy> policy;if(!policy_path.empty()){std::istringstream input(read_policy_file(policy_path));policy=agentshield::parse_policy(input);if(policy->enforce&&action!="run")throw std::invalid_argument("enforce policies are valid only with run");}
        agentshield::Privacy privacy=privacy_text=="strict"?agentshield::Privacy::strict:agentshield::Privacy::standard;if(!audit_path.empty()){audit_key=read_audit_key(audit_key_path);audit_fd=open_audit(audit_path,*audit_key,configured_audit_max);}
        if(action=="inspect"){int result=emit(pid,format,privacy,nullptr,policy?&*policy:nullptr,approvals);finalize_audit();return result;}
        std::signal(SIGINT,stop);std::signal(SIGTERM,stop);pid_t child=-1;agentshield::Assessment previous;
        if(action=="run"){
            if(command_index<0||command_index>=argc)throw std::invalid_argument("COMMAND is required after --");
            if(limits.cgroup)prepare_cgroup(limits);
            int status_pipe[2];if(pipe2(status_pipe,O_CLOEXEC)!=0)throw std::runtime_error("cannot create secure exec status channel");
            child=fork();if(child<0){close(status_pipe[0]);close(status_pipe[1]);throw std::runtime_error("fork failed");}
            bool policy_gate=policy&&policy->enforce;bool gate_before_exec=policy_gate||limits.cgroup;
            if(child==0){close(status_pipe[0]);harden_child(limits,status_pipe[1],gate_before_exec);execvp(argv[command_index],&argv[command_index]);int exec_error=errno;ssize_t ignored=write(status_pipe[1],&exec_error,sizeof exec_error);(void)ignored;_exit(127);}
            close(status_pipe[1]);
            if(setpgid(child,child)!=0&&errno!=EACCES&&errno!=ESRCH){close(status_pipe[0]);kill(child,SIGTERM);waitpid(child,nullptr,0);throw std::runtime_error("could not isolate agent process group");}
            if(gate_before_exec){int gate_status=0;if(waitpid(child,&gate_status,WUNTRACED)!=child||!WIFSTOPPED(gate_status)||WSTOPSIG(gate_status)!=SIGSTOP){close(status_pipe[0]);kill(-child,SIGKILL);waitpid(child,nullptr,0);throw std::runtime_error("could not establish the pre-exec supervision gate");}try{attach_cgroup(child);}catch(...){close(status_pipe[0]);if(ptrace(PTRACE_DETACH,child,nullptr,SIGKILL)!=0)kill(-child,SIGKILL);waitpid(child,nullptr,0);throw;}if(ptrace(PTRACE_CONT,child,nullptr,nullptr)!=0){close(status_pipe[0]);kill(-child,SIGKILL);waitpid(child,nullptr,0);throw std::runtime_error("could not continue the pre-exec supervision gate");}}
            int exec_error=0;ssize_t status_count=read(status_pipe[0],&exec_error,sizeof exec_error);close(status_pipe[0]);
            if(status_count==sizeof exec_error){waitpid(child,nullptr,0);throw std::runtime_error("cannot execute supervised command: "+std::string(std::strerror(exec_error)));}
            pid=child;
            if(gate_before_exec){int exec_status=0;if(waitpid(child,&exec_status,0)!=child||!WIFSTOPPED(exec_status)||WSTOPSIG(exec_status)!=SIGTRAP){kill(-child,SIGKILL);waitpid(child,nullptr,0);throw std::runtime_error("supervised command did not reach the protected exec boundary");}if(policy_gate){int initial_result=emit(pid,format,privacy,&previous,&*policy,approvals);if(initial_result!=0){if(ptrace(PTRACE_DETACH,child,nullptr,SIGKILL)!=0)kill(-child,SIGKILL);waitpid(child,nullptr,0);finalize_audit();cleanup_cgroup(true);return initial_result;}}if(ptrace(PTRACE_DETACH,child,nullptr,nullptr)!=0){kill(-child,SIGKILL);waitpid(child,nullptr,0);throw std::runtime_error("could not release the protected exec boundary");}}
        }
        int result=0;bool child_reaped=false;
        while(running){if(child>0){int status=0;pid_t state=waitpid(child,&status,WNOHANG);if(state==child){result=exit_result(status);child_reaped=true;terminate_group(child);break;}}int emitted=emit(pid,format,privacy,&previous,policy?&*policy:nullptr,approvals);if(emitted!=0){if(child>0){terminate_group(child);int status=0;if(waitpid(child,&status,0)==child)child_reaped=true;}result=emitted;break;}std::this_thread::sleep_for(std::chrono::milliseconds(interval));}
        if(child>0&&!child_reaped){terminate_group(child);int status=0;if(waitpid(child,&status,0)==child)result=exit_result(status);else result=1;}
        finalize_audit();cleanup_cgroup(true);return result;
    }catch(const std::exception& error){cleanup_cgroup();if(audit_fd>=0){close(audit_fd);audit_fd=-1;}if(audit_key){OPENSSL_cleanse(audit_key->data(),audit_key->size());audit_key.reset();}std::cerr<<"agentshield: "<<error.what()<<'\n';return 2;}
}
