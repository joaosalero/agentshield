#include "audit_log.hpp"
#include "risk_engine.hpp"

#include <cstddef>
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

int fuzz_one(const std::uint8_t* data,std::size_t size){
    if(size==0||size>65536)return 0;
    std::string input(reinterpret_cast<const char*>(data),size);
    try{
        if((data[0]&1U)==0){std::istringstream policy(input);(void)agentshield::parse_policy(policy);}
        else{(void)agentshield::decode_audit_record(input);}
    }catch(const std::exception&){ }
    return 0;
}

int main(){
    std::vector<std::string> seeds{
      "version 1\nmode enforce\nrequire-full-coverage true\nallow-root false\nallow-capabilities false\nmax-risk-score 50\ndefault credential approval\ndefault sensitive-file deny\ndefault network deny\n",
      "{\"schema\":\"io.agentshield.audit/v1\",\"sequence\":1,\"recordedAtMs\":1,\"previousMac\":\""+std::string(64,'0')+"\",\"eventSha256\":\""+std::string(64,'0')+"\",\"eventBase64\":\"e30=\",\"mac\":\""+std::string(64,'0')+"\"}"
    };
    std::uint32_t state=0x41534844U;
    for(std::size_t iteration=0;iteration<10000;++iteration){
        std::string input=seeds[iteration%seeds.size()];
        for(std::size_t mutation=0;mutation<1+iteration%8;++mutation){
            state^=state<<13U;state^=state>>17U;state^=state<<5U;
            if(input.empty()||(state&3U)==0)input.insert(input.begin()+static_cast<std::ptrdiff_t>(state%(input.size()+1)),static_cast<char>(state&0xffU));
            else if((state&3U)==1)input.erase(input.begin()+static_cast<std::ptrdiff_t>(state%input.size()));
            else input[state%input.size()]=static_cast<char>(state&0xffU);
            if(input.size()>4096)input.resize(4096);
        }
        fuzz_one(reinterpret_cast<const std::uint8_t*>(input.data()),input.size());
    }
}
