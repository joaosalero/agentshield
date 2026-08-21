#include "agentshield/sensor.h"
#include "risk_engine.hpp"
#include <chrono>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>
#include <unistd.h>
#include <sys/wait.h>

namespace {
volatile std::sig_atomic_t running=1;
void stop(int){running=0;}
long long now_ms(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();}
void usage(){std::cout<<"AgentShield - runtime security monitor for AI agents\n\nUsage:\n  agentshield inspect PID [--format json|tsv]\n  agentshield watch PID [--interval MS] [--format json|tsv]\n  agentshield run [--interval MS] [--format json|tsv] -- COMMAND [ARGS...]\n\nCredential values are never retained in snapshots or emitted.\n";}
int emit(int pid,const std::string& format){as_snapshot s{};char error[256];if(as_collect_snapshot(pid,&s,error,sizeof error)!=0){std::cerr<<"agentshield: "<<error<<'\n';return 1;}auto a=agentshield::assess(s);std::cout<<(format=="tsv"?agentshield::to_tsv(a,now_ms()):agentshield::to_json(a,now_ms()))<<std::flush;return 0;}
int parse_positive(const std::string& value){try{int n=std::stoi(value);if(n>0)return n;}catch(...){ }throw std::invalid_argument("expected a positive integer");}
}

int main(int argc,char** argv){
    try{
        if(argc<2||std::string(argv[1])=="--help"){usage();return argc<2?2:0;}
        std::string action=argv[1],format="json";int interval=1000,pid=0,command_index=-1;
        int i=2;if(action=="inspect"||action=="watch"){if(i>=argc)throw std::invalid_argument("PID is required");pid=parse_positive(argv[i++]);}
        for(;i<argc;++i){std::string arg=argv[i];if(arg=="--"){command_index=i+1;break;}if((arg=="--interval"||arg=="--format")&&i+1<argc){std::string v=argv[++i];if(arg=="--interval")interval=parse_positive(v);else format=v;}else throw std::invalid_argument("unknown option: "+arg);}
        if(format!="json"&&format!="tsv")throw std::invalid_argument("format must be json or tsv");
        if(action=="inspect")return emit(pid,format);
        std::signal(SIGINT,stop);std::signal(SIGTERM,stop);
        pid_t child=-1;
        if(action=="run"){
            if(command_index<0||command_index>=argc)throw std::invalid_argument("COMMAND is required after --");
            child=fork();
            if(child<0)throw std::runtime_error("fork failed");
            if(child==0){setpgid(0,0);execvp(argv[command_index],&argv[command_index]);_exit(127);}
            if(setpgid(child,child)!=0&&errno!=EACCES&&errno!=ESRCH){kill(child,SIGTERM);waitpid(child,nullptr,0);throw std::runtime_error("could not isolate agent process group");}
            pid=child;
        }else if(action!="watch")throw std::invalid_argument("unknown action: "+action);
        int result=0;
        bool child_reaped=false;
        while(running){
            if(child>0){int status=0;pid_t state=waitpid(child,&status,WNOHANG);if(state==child){result=WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status);child_reaped=true;break;}}
            if(emit(pid,format)!=0){if(child>0){int status=0;if(waitpid(child,&status,0)==child){result=WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status);child_reaped=true;}}break;}
            std::this_thread::sleep_for(std::chrono::milliseconds(interval));
        }
        if(child>0&&!child_reaped){int status=0;if(waitpid(child,&status,WNOHANG)==0){kill(-child,SIGTERM);waitpid(child,&status,0);}result=WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status);}
        return result;
    }catch(const std::exception& e){std::cerr<<"agentshield: "<<e.what()<<'\n';return 2;}
}
