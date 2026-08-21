#include "agentshield/sensor.h"
#include "risk_engine.hpp"

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

namespace {
volatile std::sig_atomic_t running=1;
int audit_fd=-1;
struct RunLimits { int memory_mb=0; int cpu_seconds=0; int processes=0; bool no_new_privileges=true; bool inherit_output=false; bool inherit_input=false; };
void stop(int){running=0;}
long long now_ms(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();}

void usage(){
    std::cout << "AgentShield - runtime security monitor for AI agents\n\nUsage:\n"
      "  agentshield inspect PID [OPTIONS]\n  agentshield watch PID [OPTIONS]\n"
      "  agentshield run [OPTIONS] -- COMMAND [ARGS...]\n\nOptions:\n"
      "  --format json|tsv          Output format (default: json)\n"
      "  --privacy standard|strict Strict redacts credential names and paths\n"
      "  --interval MS              Watch interval (default: 1000)\n"
      "  --audit FILE               Append JSONL to an owner-only regular file\n"
      "  --max-memory-mb N          Supervised process address-space limit\n"
      "  --max-cpu-seconds N        Supervised process CPU limit\n"
      "  --max-processes N          Supervised process count limit\n"
      "  --agent-output MODE        discard (default) or inherit to stderr\n"
      "  --agent-input MODE         discard (default) or inherit\n"
      "  --allow-new-privs          Disable the default no_new_privs control\n\n"
      "Credential values and command arguments are never retained in snapshots or emitted.\n";
}

int parse_positive(const std::string& value){
    try{size_t used=0;int n=std::stoi(value,&used);if(n>0&&used==value.size())return n;}catch(...){ }
    throw std::invalid_argument("expected a positive integer");
}
void write_all(int fd,const std::string& data){
    size_t offset=0;while(offset<data.size()){ssize_t count=write(fd,data.data()+offset,data.size()-offset);if(count<0&&errno==EINTR)continue;if(count<=0)throw std::runtime_error("secure audit write failed");offset+=static_cast<size_t>(count);}
}
int open_audit(const std::string& path){
    int fd=open(path.c_str(),O_WRONLY|O_APPEND|O_CREAT|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK,0600);
    if(fd<0)throw std::runtime_error("cannot open audit file safely: "+std::string(std::strerror(errno)));
    struct stat status{};
    if(fstat(fd,&status)!=0||!S_ISREG(status.st_mode)||status.st_uid!=geteuid()||(status.st_mode&0077)!=0){close(fd);throw std::runtime_error("audit file must be a regular, owner-only file owned by the current user");}
    int flags=fcntl(fd,F_GETFL);
    if(flags<0||fcntl(fd,F_SETFL,flags&~O_NONBLOCK)!=0){close(fd);throw std::runtime_error("cannot configure audit file safely");}
    return fd;
}
int emit(int pid,const std::string& format,agentshield::Privacy privacy){
    as_snapshot snapshot{};char error[256];if(as_collect_snapshot(pid,&snapshot,error,sizeof error)!=0){std::cerr<<"agentshield: "<<error<<'\n';return 1;}
    auto assessment=agentshield::assess(snapshot);long long timestamp=now_ms();std::string json=agentshield::to_json(assessment,timestamp,privacy);std::cout<<(format=="tsv"?agentshield::to_tsv(assessment,timestamp,privacy):json)<<std::flush;
    if(audit_fd>=0){try{write_all(audit_fd,json);}catch(const std::exception& error){std::cerr<<"agentshield: "<<error.what()<<'\n';return 1;}}
    return 0;
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
void harden_child(const RunLimits& limits,int status_fd){
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
}
int exit_result(int status){return WIFEXITED(status)?WEXITSTATUS(status):WIFSIGNALED(status)?128+WTERMSIG(status):1;}
void harden_monitor(){
    struct rlimit limit{0,0};
    if(setrlimit(RLIMIT_CORE,&limit)!=0||prctl(PR_SET_DUMPABLE,0)!=0)throw std::runtime_error("cannot disable monitor memory dumps");
}
void terminate_group(pid_t group){
    if(group<=0)return;
    if(kill(-group,SIGTERM)!=0&&errno==ESRCH)return;
    for(int attempt=0;attempt<20;++attempt){
        if(kill(-group,0)!=0&&errno==ESRCH)return;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    if(kill(-group,SIGKILL)!=0&&errno!=ESRCH)std::cerr<<"agentshield: warning: process-group kill failed\n";
}
}

int main(int argc,char** argv){
    try{
        harden_monitor();
        if(argc<2||std::string(argv[1])=="--help"){usage();return argc<2?2:0;}
        std::string action=argv[1],format="json",privacy_text="standard",audit_path;int interval=1000,pid=0,command_index=-1;RunLimits limits;
        int i=2;if(action=="inspect"||action=="watch"){if(i>=argc)throw std::invalid_argument("PID is required");pid=parse_positive(argv[i++]);}
        for(;i<argc;++i){std::string argument=argv[i];if(argument=="--"){command_index=i+1;break;}if(argument=="--allow-new-privs"){limits.no_new_privileges=false;continue;}
            if((argument=="--interval"||argument=="--format"||argument=="--privacy"||argument=="--audit"||argument=="--max-memory-mb"||argument=="--max-cpu-seconds"||argument=="--max-processes"||argument=="--agent-output"||argument=="--agent-input")&&i+1<argc){std::string value=argv[++i];if(argument=="--interval")interval=parse_positive(value);else if(argument=="--format")format=value;else if(argument=="--privacy")privacy_text=value;else if(argument=="--audit")audit_path=value;else if(argument=="--max-memory-mb")limits.memory_mb=parse_positive(value);else if(argument=="--max-cpu-seconds")limits.cpu_seconds=parse_positive(value);else if(argument=="--max-processes")limits.processes=parse_positive(value);else if(argument=="--agent-output"){if(value=="inherit")limits.inherit_output=true;else if(value!="discard")throw std::invalid_argument("agent output must be discard or inherit");}else{if(value=="inherit")limits.inherit_input=true;else if(value!="discard")throw std::invalid_argument("agent input must be discard or inherit");}continue;}throw std::invalid_argument("unknown or incomplete option: "+argument);}
        if(format!="json"&&format!="tsv")throw std::invalid_argument("format must be json or tsv");
        if(privacy_text!="standard"&&privacy_text!="strict")throw std::invalid_argument("privacy must be standard or strict");
        if(action!="inspect"&&action!="watch"&&action!="run")throw std::invalid_argument("unknown action: "+action);
        if(action!="run"&&(limits.memory_mb||limits.cpu_seconds||limits.processes||!limits.no_new_privileges||limits.inherit_output||limits.inherit_input))throw std::invalid_argument("process controls are valid only with run");
        agentshield::Privacy privacy=privacy_text=="strict"?agentshield::Privacy::strict:agentshield::Privacy::standard;if(!audit_path.empty())audit_fd=open_audit(audit_path);
        if(action=="inspect"){int result=emit(pid,format,privacy);if(audit_fd>=0)close(audit_fd);return result;}
        std::signal(SIGINT,stop);std::signal(SIGTERM,stop);pid_t child=-1;
        if(action=="run"){
            if(command_index<0||command_index>=argc)throw std::invalid_argument("COMMAND is required after --");
            int status_pipe[2];if(pipe2(status_pipe,O_CLOEXEC)!=0)throw std::runtime_error("cannot create secure exec status channel");
            child=fork();if(child<0){close(status_pipe[0]);close(status_pipe[1]);throw std::runtime_error("fork failed");}
            if(child==0){close(status_pipe[0]);harden_child(limits,status_pipe[1]);execvp(argv[command_index],&argv[command_index]);int exec_error=errno;ssize_t ignored=write(status_pipe[1],&exec_error,sizeof exec_error);(void)ignored;_exit(127);}
            close(status_pipe[1]);
            if(setpgid(child,child)!=0&&errno!=EACCES&&errno!=ESRCH){close(status_pipe[0]);kill(child,SIGTERM);waitpid(child,nullptr,0);throw std::runtime_error("could not isolate agent process group");}
            int exec_error=0;ssize_t status_count=read(status_pipe[0],&exec_error,sizeof exec_error);close(status_pipe[0]);
            if(status_count==sizeof exec_error){waitpid(child,nullptr,0);throw std::runtime_error("cannot execute supervised command: "+std::string(std::strerror(exec_error)));}
            pid=child;
        }
        int result=0;bool child_reaped=false;
        while(running){if(child>0){int status=0;pid_t state=waitpid(child,&status,WNOHANG);if(state==child){result=exit_result(status);child_reaped=true;terminate_group(child);break;}}if(emit(pid,format,privacy)!=0){if(child>0){terminate_group(child);int status=0;if(waitpid(child,&status,0)==child)child_reaped=true;}result=1;break;}std::this_thread::sleep_for(std::chrono::milliseconds(interval));}
        if(child>0&&!child_reaped){terminate_group(child);int status=0;if(waitpid(child,&status,0)==child)result=exit_result(status);else result=1;}
        if(audit_fd>=0){if(fsync(audit_fd)!=0)throw std::runtime_error("audit synchronization failed");close(audit_fd);audit_fd=-1;}return result;
    }catch(const std::exception& error){if(audit_fd>=0)close(audit_fd);std::cerr<<"agentshield: "<<error.what()<<'\n';return 2;}
}
