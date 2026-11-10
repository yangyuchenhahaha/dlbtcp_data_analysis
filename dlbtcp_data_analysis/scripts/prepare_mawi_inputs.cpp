// Streaming input restoration and exact phase-1 accounting. No window/event analysis.
#include <algorithm>
#include <array>
#include <arpa/inet.h>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

struct Key { uint32_t a, ap, b, bp; bool operator==(const Key& k) const { return a==k.a && ap==k.ap && b==k.b && bp==k.bp; } };
struct KeyHash { size_t operator()(const Key& k) const { uint64_t x=(uint64_t(k.a)<<32)|k.b; uint64_t y=(uint64_t(k.ap)<<32)|k.bp; x^=y+0x9e3779b97f4a7c15ULL+(x<<6)+(x>>2); x^=x>>30; x*=0xbf58476d1ce4e5b9ULL; x^=x>>27; x*=0x94d049bb133111ebULL; return x^(x>>31); } };
struct Counts { uint32_t packets=0; uint8_t dirs=0; };
struct TimeStats {
    uint64_t count=0, backwards=0; int64_t first=0,last=0,min=0,max=0,max_backward=0;
    void add(int64_t ts) { if (!count) first=min=max=ts; else { if(ts<last){++backwards;max_backward=std::max(max_backward,last-ts);} min=std::min(min,ts);max=std::max(max,ts); } last=ts;++count; }
};
struct Endpoint { std::string ip; uint32_t id; uint64_t packets=0,tx=0,rx=0,wire=0,payload=0,conns=0,both=0,large=0,large_both=0; TimeStats time; };
static const std::array<const char*,16> names={"ts","proto","src","dst","sport","dport","l4len","plen","flags","seq","ack","win","thl","caplen","wirelen","opts_trunc"};
static std::string quoted(const std::string& x){std::ostringstream o;o<<'"';for(char c:x){if(c=='"'||c=='\\')o<<'\\'; if(c=='\n')o<<"\\n";else if(c=='\r')o<<"\\r";else o<<c;}o<<'"';return o.str();}
static int64_t integer(std::string_view s){ bool negative=false; size_t i=0; if(!s.empty()&&s[0]=='-'){negative=true;i=1;} if(i==s.size())throw std::runtime_error("empty integer");int64_t n=0;for(;i<s.size();++i){if(s[i]<'0'||s[i]>'9')throw std::runtime_error("invalid integer");n=n*10+(s[i]-'0');}return negative?-n:n; }
static int64_t time_ns(std::string_view s){auto dot=s.find('.');if(dot==std::string_view::npos)return integer(s)*1000000000LL;int64_t n=integer(s.substr(0,dot))*1000000000LL;auto f=s.substr(dot+1);if(f.size()>9)throw std::runtime_error("timestamp finer than ns");int64_t v=integer(f);for(size_t i=f.size();i<9;++i)v*=10;return n+v;}
static std::string ts_text(int64_t ns){std::ostringstream o;o<<ns/1000000000LL<<'.'<<std::setw(9)<<std::setfill('0')<<ns%1000000000LL;return o.str();}
static void write_time(std::ostream& o,const TimeStats& t){o<<"{\"rows\":"<<t.count<<",\"first_ts\":"<<(t.count?quoted(ts_text(t.first)):"null")<<",\"last_ts\":"<<(t.count?quoted(ts_text(t.last)):"null")<<",\"min_ts\":"<<(t.count?quoted(ts_text(t.min)):"null")<<",\"max_ts\":"<<(t.count?quoted(ts_text(t.max)):"null")<<",\"timestamp_backwards\":"<<t.backwards<<",\"max_backward_ns\":"<<t.max_backward<<",\"max_backward_s\":"<<double(t.max_backward)/1e9<<'}';}
static bool valid_ip(const std::string& ip){unsigned char bytes[16];return inet_pton(AF_INET,ip.c_str(),bytes)==1||inet_pton(AF_INET6,ip.c_str(),bytes)==1;}
int main(int argc,char** argv){try{
    if(argc<6){std::cerr<<"usage: prepare_mawi_inputs input.tsv tcp.part selected.part report.json ip [ip ...]\n";return 2;}
    std::ifstream input(argv[1]);std::ofstream tcp(argv[2]),selected(argv[3]); if(!input||!tcp||!selected)throw std::runtime_error("cannot open input/output");
    std::unordered_map<std::string,uint32_t> ip_ids;ip_ids.reserve(1000000);std::vector<uint8_t> ip_valid;
    auto intern=[&](std::string_view text){std::string s(text);auto it=ip_ids.find(s);if(it!=ip_ids.end())return it->second;uint32_t id=ip_ids.size();ip_valid.push_back(valid_ip(s));ip_ids.emplace(std::move(s),id);return id;};
    std::vector<Endpoint> endpoints;std::unordered_map<uint32_t,size_t> selected_ids;for(int i=5;i<argc;++i){uint32_t id=intern(argv[i]);if(!ip_valid[id])throw std::runtime_error("invalid selected IP");selected_ids[id]=endpoints.size();endpoints.push_back({argv[i],id});}
    std::unordered_map<Key,Counts,KeyHash> connections;connections.max_load_factor(.8f);connections.reserve(16000000);
    std::array<uint64_t,16> all_valid{},tcp_valid{};TimeStats all_time,tcp_time,subset_time;
    uint64_t rows=0,ntcp=0,nudp=0,nselected=0,options_truncated=0,options_truncated_known=0,options_truncated_unknown=0,negative_flags=0,negative_thl=0,invalid_thl=0,invalid_fixed=0,unknown_ports=0,invalid_payload=0;
    std::string line;line.reserve(256);std::array<std::string_view,16> c;std::array<int64_t,16> value{};
    while(std::getline(input,line)){
        if(line.empty()||line[0]=='#')continue;size_t start=0;for(int i=0;i<16;++i){size_t end=line.find('\t',start);if(i<15&&end==std::string::npos)throw std::runtime_error("row lacks 16 columns");if(i==15&&end!=std::string::npos)throw std::runtime_error("row has extra columns");if(end==std::string::npos)end=line.size();c[i]=std::string_view(line).substr(start,end-start);start=end+1;}
        value[0]=time_ns(c[0]);for(int i=1;i<16;++i)if(i!=2&&i!=3)value[i]=integer(c[i]);
        uint32_t src=intern(c[2]),dst=intern(c[3]);const bool is_tcp=value[1]==6;
        const bool thl_ok=is_tcp?(value[12]>=20&&value[12]<=60&&value[12]%4==0):(value[1]==17&&value[12]==8);
        const bool ports_ok=value[4]>=0&&value[4]<=65535&&value[5]>=0&&value[5]<=65535;
        std::array<bool,16> valid={value[0]>=0,value[1]>=0&&value[1]<=255,bool(ip_valid[src]),bool(ip_valid[dst]),value[4]>=0&&value[4]<=65535,value[5]>=0&&value[5]<=65535,value[6]>=0,value[7]>=0&&value[7]<=value[6],value[8]>=0&&value[8]<=255,value[9]>=0&&value[9]<=4294967295LL,value[10]>=0&&value[10]<=4294967295LL,value[11]>=0&&value[11]<=65535,thl_ok,value[13]>=0&&value[13]<=value[14],value[14]>=0,value[15]==0||value[15]==1};
        for(int i=0;i<16;++i){all_valid[i]+=valid[i];if(is_tcp)tcp_valid[i]+=valid[i];}
        ++rows;all_time.add(value[0]);if(value[1]==17)++nudp;
        if(!is_tcp)continue;++ntcp;tcp_time.add(value[0]);tcp<<line<<'\n';
        options_truncated+=value[15]>0;options_truncated_known+=(value[15]>0&&value[8]>=0&&thl_ok&&ports_ok);options_truncated_unknown+=(value[15]>0&&(value[8]<0||!thl_ok||!ports_ok));negative_flags+=value[8]<0;negative_thl+=value[12]<0;invalid_thl+=!thl_ok;unknown_ports+=!ports_ok;invalid_fixed+=(value[8]<0||!thl_ok||!ports_ok);invalid_payload+=!valid[7];
        uint32_t sp=value[4]<0?65536:uint32_t(value[4]),dp=value[5]<0?65536:uint32_t(value[5]);bool reverse=src>dst||(src==dst&&sp>dp);Key key=reverse?Key{dst,dp,src,sp}:Key{src,sp,dst,dp};auto& count=connections[key];if(count.packets==std::numeric_limits<uint32_t>::max())throw std::runtime_error("connection packet counter overflow");++count.packets;count.dirs|=reverse?2:1;
        auto si=selected_ids.find(src),di=selected_ids.find(dst);if(si!=selected_ids.end()||di!=selected_ids.end()){++nselected;subset_time.add(value[0]);selected<<line<<'\n';}
        if(si!=selected_ids.end()){auto& ep=endpoints[si->second];++ep.packets;++ep.tx;ep.wire+=std::max<int64_t>(0,value[14]);ep.payload+=std::max<int64_t>(0,value[7]);ep.time.add(value[0]);}
        if(di!=selected_ids.end()&&src!=dst){auto& ep=endpoints[di->second];++ep.packets;++ep.rx;ep.wire+=std::max<int64_t>(0,value[14]);ep.payload+=std::max<int64_t>(0,value[7]);ep.time.add(value[0]);}
        if(rows%10000000==0)std::cerr<<"rows "<<rows<<", TCP "<<ntcp<<", unique connections "<<connections.size()<<'\n';
    }
    if(input.bad()||!tcp||!selected)throw std::runtime_error("I/O error");tcp.close();selected.close();if(!tcp||!selected)throw std::runtime_error("output close/flush error");
    uint64_t both=0,both_packets=0,large=0,large_both=0,one=0,two=0,subset_conns=0;
    for(const auto& item:connections){const auto& k=item.first;const auto& v=item.second;const bool b=v.dirs==3,g=v.packets>=100;both+=b;both_packets+=b?v.packets:0;large+=g;large_both+=g&&b;one+=v.packets==1;two+=v.packets==2;
        auto ai=selected_ids.find(k.a),bi=selected_ids.find(k.b);subset_conns+=ai!=selected_ids.end()||bi!=selected_ids.end();
        if(ai!=selected_ids.end()){auto& ep=endpoints[ai->second];++ep.conns;ep.both+=b;ep.large+=g;ep.large_both+=g&&b;}
        if(bi!=selected_ids.end()&&k.a!=k.b){auto& ep=endpoints[bi->second];++ep.conns;ep.both+=b;ep.large+=g;ep.large_both+=g&&b;}
    }
    std::ofstream out(argv[4]);if(!out)throw std::runtime_error("cannot create stats JSON");out<<std::setprecision(17);
    out<<"{\n\"input\":"<<quoted(argv[1])<<",\"rows_total\":"<<rows<<",\"tcp_pkts\":"<<ntcp<<",\"udp_pkts\":"<<nudp<<",\"tcp_connections\":"<<connections.size()<<",\"tcp_connections_both_dirs\":"<<both<<",\"pkts_in_both_dir_conns\":"<<both_packets<<",\"conn_both_dirs_frac\":"<<double(both)/connections.size()<<",\"pkts_in_both_dir_conns_frac\":"<<double(both_packets)/ntcp<<",\"conns_ge100pkts\":"<<large<<",\"conns_ge100pkts_both_dirs\":"<<large_both<<",\"conns_ge100pkts_both_frac\":"<<(large?double(large_both)/large:0)<<",\"conns_1pkt\":"<<one<<",\"conns_2pkts\":"<<two<<",\"selected_packets\":"<<nselected<<",\"selected_connections\":"<<subset_conns<<",\"tcp_options_truncated\":"<<options_truncated<<",\"tcp_options_truncated_known_tcp_header\":"<<options_truncated_known<<",\"tcp_options_truncated_unknown_tcp_header\":"<<options_truncated_unknown<<",\"tcp_negative_flags\":"<<negative_flags<<",\"tcp_negative_thl\":"<<negative_thl<<",\"tcp_invalid_thl\":"<<invalid_thl<<",\"tcp_unknown_ports_packets\":"<<unknown_ports<<",\"tcp_invalid_fixed_header_packets\":"<<invalid_fixed<<",\"tcp_invalid_payload_length_packets\":"<<invalid_payload<<",\n\"capture_order_timestamps\":{\"all_emitted\":";write_time(out,all_time);out<<",\"tcp\":";write_time(out,tcp_time);out<<",\"selected\":";write_time(out,subset_time);out<<"},\n\"field_validity_definitions\":{\"rate\":\"syntactic/range validity per column, not an any-row flag\",\"thl\":\"TCP 20..60 and multiple of 4; UDP 8\",\"plen\":\"nonnegative and at most l4len; invalid TCP thl still makes interpretation uncertain\",\"opts_trunc\":\"column 16 as emitted by converter; no assumed Ethernet/IP offset\",\"udp_placeholders\":\"UDP flags/seq/ack/win values are placeholders and are not TCP evidence\",\"connection\":\"canonical IP/port pair; same-IP ports normalized; TCP sessions sharing tuple not split\"},\n\"tcp_field_validity\":{";
    for(int i=0;i<16;++i){if(i)out<<',';out<<quoted(names[i])<<":{\"valid_rows\":"<<tcp_valid[i]<<",\"total_rows\":"<<ntcp<<",\"valid_fraction\":"<<double(tcp_valid[i])/ntcp<<'}';}out<<"},\n\"all_emitted_field_validity\":{";
    for(int i=0;i<16;++i){if(i)out<<',';out<<quoted(names[i])<<":{\"valid_rows\":"<<all_valid[i]<<",\"total_rows\":"<<rows<<",\"valid_fraction\":"<<double(all_valid[i])/rows<<'}';}out<<"},\n\"selected_endpoints\": [";
    for(size_t i=0;i<endpoints.size();++i){if(i)out<<',';const auto& ep=endpoints[i];out<<"{\"ip\":"<<quoted(ep.ip)<<",\"packets\":"<<ep.packets<<",\"tx\":"<<ep.tx<<",\"rx\":"<<ep.rx<<",\"wire_bytes\":"<<ep.wire<<",\"payload_bytes\":"<<ep.payload<<",\"connections\":"<<ep.conns<<",\"connections_both_dirs\":"<<ep.both<<",\"conns_ge100pkts\":"<<ep.large<<",\"conns_ge100pkts_both_dirs\":"<<ep.large_both<<",\"capture_order_timestamps\":";write_time(out,ep.time);out<<'}';}
    out<<"]\n}\n";if(!out)throw std::runtime_error("JSON write error");std::cerr<<"complete: "<<rows<<" rows, "<<ntcp<<" TCP, "<<connections.size()<<" connections\n";
    return 0;
}catch(const std::exception& e){std::cerr<<"prepare_mawi_inputs: "<<e.what()<<'\n';return 1;}}
