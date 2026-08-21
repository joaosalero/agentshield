#include "audit_log.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <iomanip>
#include <limits>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <sstream>
#include <stdexcept>

namespace agentshield {
namespace {

constexpr char kZeroMac[] =
    "0000000000000000000000000000000000000000000000000000000000000000";

std::string hex(const std::uint8_t* data,std::size_t size){std::ostringstream out;out<<std::hex<<std::setfill('0');for(std::size_t i=0;i<size;++i)out<<std::setw(2)<<static_cast<unsigned>(data[i]);return out.str();}
int hex_value(char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;}
bool valid_hex64(const std::string& value){return value.size()==64&&std::all_of(value.begin(),value.end(),[](char c){return hex_value(c)>=0;});}
bool secure_equal(const std::string& left,const std::string& right){return left.size()==right.size()&&CRYPTO_memcmp(left.data(),right.data(),left.size())==0;}

std::string base64_encode(const std::string& value){static constexpr char table[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";std::string out;out.reserve((value.size()+2)/3*4);for(std::size_t i=0;i<value.size();i+=3){std::uint32_t n=static_cast<unsigned char>(value[i])<<16U;if(i+1<value.size())n|=static_cast<unsigned char>(value[i+1])<<8U;if(i+2<value.size())n|=static_cast<unsigned char>(value[i+2]);out.push_back(table[(n>>18U)&63U]);out.push_back(table[(n>>12U)&63U]);out.push_back(i+1<value.size()?table[(n>>6U)&63U]:'=');out.push_back(i+2<value.size()?table[n&63U]:'=');}return out;}
std::string base64_decode(const std::string& value){if(value.size()%4!=0)throw std::invalid_argument("invalid audit event encoding");std::array<int,256> map{};map.fill(-1);std::string alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";for(std::size_t i=0;i<alphabet.size();++i)map[static_cast<unsigned char>(alphabet[i])]=static_cast<int>(i);std::string out;out.reserve(value.size()/4*3);for(std::size_t i=0;i<value.size();i+=4){int a=map[static_cast<unsigned char>(value[i])],b=map[static_cast<unsigned char>(value[i+1])];if(a<0||b<0)throw std::invalid_argument("invalid audit event encoding");bool pad2=value[i+2]=='=',pad3=value[i+3]=='=';if(pad2&&!pad3)throw std::invalid_argument("invalid audit event padding");int c=pad2?0:map[static_cast<unsigned char>(value[i+2])],d=pad3?0:map[static_cast<unsigned char>(value[i+3])];if(c<0||d<0||(i+4!=value.size()&&(pad2||pad3)))throw std::invalid_argument("invalid audit event encoding");std::uint32_t n=static_cast<std::uint32_t>((a<<18)|(b<<12)|(c<<6)|d);out.push_back(static_cast<char>((n>>16)&255));if(!pad2)out.push_back(static_cast<char>((n>>8)&255));if(!pad3)out.push_back(static_cast<char>(n&255));}if(base64_encode(out)!=value)throw std::invalid_argument("non-canonical audit event encoding");return out;}

std::string json_escape(const std::string& value){std::ostringstream out;for(unsigned char c:value){switch(c){case '"':out<<"\\\"";break;case '\\':out<<"\\\\";break;case '\n':out<<"\\n";break;case '\r':out<<"\\r";break;case '\t':out<<"\\t";break;default:if(c>=0x20)out<<c;}}return out.str();}
std::string mac_payload(const AuditRecord& r){return "io.agentshield.audit/v1\n"+std::to_string(r.sequence)+"\n"+std::to_string(r.recorded_at_ms)+"\n"+r.previous_mac+"\n"+r.event_sha256+"\n"+base64_encode(r.event_json);}

std::string take(std::string& source,const std::string& prefix,const std::string& suffix){if(source.compare(0,prefix.size(),prefix)!=0)throw std::invalid_argument("invalid audit record structure");source.erase(0,prefix.size());auto end=source.find(suffix);if(end==std::string::npos)throw std::invalid_argument("invalid audit record structure");std::string result=source.substr(0,end);source.erase(0,end+suffix.size());return result;}
std::uint64_t parse_u64(const std::string& value){if(value.empty()||!std::all_of(value.begin(),value.end(),[](unsigned char c){return std::isdigit(c);}))throw std::invalid_argument("invalid audit sequence");std::size_t used=0;unsigned long long parsed=std::stoull(value,&used);if(used!=value.size())throw std::invalid_argument("invalid audit sequence");return parsed;}
std::int64_t parse_i64(const std::string& value){if(value.empty()||!std::all_of(value.begin(),value.end(),[](unsigned char c){return std::isdigit(c);}))throw std::invalid_argument("invalid audit timestamp");std::size_t used=0;long long parsed=std::stoll(value,&used);if(used!=value.size())throw std::invalid_argument("invalid audit timestamp");return parsed;}

}  // namespace

std::string audit_key_to_hex(const AuditKey& key){return hex(key.data(),key.size());}
AuditKey audit_key_from_hex(const std::string& text){std::string value=text;while(!value.empty()&&(value.back()=='\n'||value.back()=='\r'))value.pop_back();if(!valid_hex64(value))throw std::invalid_argument("audit key must contain exactly 32 bytes encoded as 64 hexadecimal characters");AuditKey key{};for(std::size_t i=0;i<key.size();++i)key[i]=static_cast<std::uint8_t>((hex_value(value[i*2])<<4)|hex_value(value[i*2+1]));return key;}
std::string sha256_hex(const std::string& value){std::array<unsigned char,EVP_MAX_MD_SIZE> digest{};unsigned length=0;if(EVP_Digest(value.data(),value.size(),digest.data(),&length,EVP_sha256(),nullptr)!=1||length!=32)throw std::runtime_error("OpenSSL SHA-256 failed");return hex(digest.data(),length);}
std::string hmac_sha256_hex(const AuditKey& key,const std::string& value){std::array<unsigned char,32> result{};std::size_t length=0;if(EVP_Q_mac(nullptr,"HMAC",nullptr,"SHA256",nullptr,key.data(),key.size(),reinterpret_cast<const unsigned char*>(value.data()),value.size(),result.data(),result.size(),&length)==nullptr||length!=result.size())throw std::runtime_error("OpenSSL HMAC-SHA-256 failed");return hex(result.data(),result.size());}

std::string encode_audit_record(const AuditRecord& input,const AuditKey& key){AuditRecord r=input;if(r.sequence==0||r.recorded_at_ms<0||!valid_hex64(r.previous_mac))throw std::invalid_argument("invalid audit record metadata");r.event_sha256=sha256_hex(r.event_json);r.mac=hmac_sha256_hex(key,mac_payload(r));return "{\"schema\":\"io.agentshield.audit/v1\",\"sequence\":"+std::to_string(r.sequence)+",\"recordedAtMs\":"+std::to_string(r.recorded_at_ms)+",\"previousMac\":\""+r.previous_mac+"\",\"eventSha256\":\""+r.event_sha256+"\",\"eventBase64\":\""+base64_encode(r.event_json)+"\",\"mac\":\""+r.mac+"\"}\n";}

AuditRecord decode_audit_record(const std::string& line){std::string value=line;if(!value.empty()&&value.back()=='\r')value.pop_back();AuditRecord r;std::string seq=take(value,"{\"schema\":\"io.agentshield.audit/v1\",\"sequence\":",",\"recordedAtMs\":");std::string timestamp=take(value,"",",\"previousMac\":\"");r.previous_mac=take(value,"","\",\"eventSha256\":\"");r.event_sha256=take(value,"","\",\"eventBase64\":\"");std::string event=take(value,"","\",\"mac\":\"");r.mac=take(value,"","\"}");if(!value.empty()||!valid_hex64(r.previous_mac)||!valid_hex64(r.event_sha256)||!valid_hex64(r.mac))throw std::invalid_argument("invalid audit record fields");r.sequence=parse_u64(seq);r.recorded_at_ms=parse_i64(timestamp);r.event_json=base64_decode(event);return r;}

AuditVerification verify_audit_stream(std::istream& input,const AuditKey& key,std::vector<AuditRecord>* records){AuditVerification result;result.final_mac=kZeroMac;std::string line;while(std::getline(input,line)){if(line.empty())throw std::invalid_argument("empty line in audit log");AuditRecord r=decode_audit_record(line);if(r.sequence!=result.records+1)throw std::invalid_argument("audit sequence discontinuity at record "+std::to_string(result.records+1));if(!secure_equal(r.previous_mac,result.final_mac))throw std::invalid_argument("audit chain mismatch at record "+std::to_string(r.sequence));if(!secure_equal(sha256_hex(r.event_json),r.event_sha256))throw std::invalid_argument("audit event digest mismatch at record "+std::to_string(r.sequence));if(!secure_equal(hmac_sha256_hex(key,mac_payload(r)),r.mac))throw std::invalid_argument("audit authentication failed at record "+std::to_string(r.sequence));result.records=r.sequence;result.final_mac=r.mac;if(records)records->push_back(std::move(r));}return result;}

std::string helix_export_json(const AuditRecord& r){std::string event=r.event_json;while(!event.empty()&&(event.back()=='\n'||event.back()=='\r'))event.pop_back();if(event.empty()||event.front()!='{'||event.back()!='}')throw std::invalid_argument("audit event is not a JSON object");return "{\"schema\":\"io.helix-sentinel.agentshield/v1\",\"sequence\":"+std::to_string(r.sequence)+",\"recordedAtMs\":"+std::to_string(r.recorded_at_ms)+",\"integrity\":{\"verified\":true,\"algorithm\":\"HMAC-SHA-256\",\"mac\":\""+json_escape(r.mac)+"\"},\"event\":"+event+"}\n";}

}  // namespace agentshield
