/* Inventory every capture record before protocol filtering. Build: gcc -O3 pcap_inventory.c -lpcap -o pcap_inventory */
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

static unsigned rd16(const unsigned char *p) { return p[0]*256u+p[1]; }
int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr,"usage: pcap_inventory file.pcap\n"); return 2; }
    char err[PCAP_ERRBUF_SIZE]; pcap_t *pc=pcap_open_offline(argv[1],err);
    if (!pc) { fprintf(stderr,"%s\n",err); return 1; }
    int lt=pcap_datalink(pc),r; struct pcap_pkthdr *h; const unsigned char *pkt;
    uint64_t n=0,wire=0,captured=0,truncated=0,proto[256]={0},v4=0,v6=0,other=0,shorts=0;
    uint64_t gap100=0,gap1=0,backwards=0,tcp_fixed_missing=0,tcp_options_cut=0,tcp_invalid=0;
    double first=0,last=0,prev=0,maxgap=0,maxbackward=0,gap100sum=0,gap1sum=0,mindt=1e99;
    unsigned maxcap=0;
    while ((r=pcap_next_ex(pc,&h,&pkt))==1) {
        double t=h->ts.tv_sec+h->ts.tv_usec/1e6;
        if (!n) first=t; else { double d=t-prev; if(d<0){backwards++;if(-d>maxbackward)maxbackward=-d;} if(d>maxgap)maxgap=d;
            if(d>0&&d<mindt){mindt=d;} if(d>.1){gap100++;gap100sum+=d;} if(d>1){gap1++;gap1sum+=d;} }
        last=prev=t; n++; wire+=h->len;captured+=h->caplen;truncated+=h->caplen<h->len;
        if(h->caplen>maxcap)maxcap=h->caplen;
        const unsigned char *p=pkt; unsigned rem=h->caplen,et=0;
        if(lt==1){if(rem<14){shorts++;continue;}et=rd16(p+12);p+=14;rem-=14;
            while(et==0x8100||et==0x88a8){if(rem<4){shorts++;break;}et=rd16(p+2);p+=4;rem-=4;}}
        else if(lt==12||lt==101||lt==228||lt==229){if(!rem){shorts++;continue;}et=p[0]>>4==6?0x86dd:0x0800;}
        else if(lt==113){if(rem<16){shorts++;continue;}et=rd16(p+14);p+=16;rem-=16;}
        else {other++;continue;}
        unsigned pr,iph,iplen;
        if(et==0x0800){if(rem<20){shorts++;continue;}v4++;iph=(p[0]&15)*4;pr=p[9];proto[pr]++;
            if(iph<20||rem<iph){shorts++;continue;}if(rd16(p+6)&0x1fff)continue;
            iplen=rd16(p+2);if(iplen<iph){shorts++;continue;}iplen-=iph;p+=iph;rem-=iph;}
        else if(et==0x86dd){if(rem<40){shorts++;continue;}v6++;pr=p[6];iplen=rd16(p+4);p+=40;rem-=40;
            unsigned guard=8;
            while(guard--&&(pr==0||pr==43||pr==60||pr==44)){
                if(rem<8){shorts++;break;}unsigned sz=pr==44?8:(p[1]+1)*8;
                if(pr==44&&(rd16(p+2)&0xfff8)){pr=44;break;}
                if(rem<sz||iplen<sz){shorts++;break;}pr=p[0];p+=sz;rem-=sz;iplen-=sz;
            }proto[pr]++;}
        else{other++;continue;}
        if(pr==6){if(rem<20){tcp_fixed_missing++;continue;}unsigned th=(p[12]>>4)*4;
            if(th<20||th>iplen)tcp_invalid++;else if(rem<th)tcp_options_cut++;}
    }
    if(r==-1){fprintf(stderr,"%s\n",pcap_geterr(pc));pcap_close(pc);return 1;}
    pcap_close(pc);
    printf("{\n\"packets\":%llu,\"linktype\":%d,\"first_ts\":%.6f,\"last_ts\":%.6f,\"duration_s\":%.6f,\n",
        (unsigned long long)n,lt,first,last,last-first);
    printf("\"wire_bytes\":%llu,\"captured_bytes\":%llu,\"truncated_packets\":%llu,\"max_caplen\":%u,\n",
        (unsigned long long)wire,(unsigned long long)captured,(unsigned long long)truncated,maxcap);
    printf("\"ipv4\":%llu,\"ipv6\":%llu,\"non_ip_or_unsupported\":%llu,\"short_headers\":%llu,\n",
        (unsigned long long)v4,(unsigned long long)v6,(unsigned long long)other,(unsigned long long)shorts);
    printf("\"timestamp_backwards\":%llu,\"min_positive_delta_s\":%.9f,\"max_gap_s\":%.9f,\"max_backward_s\":%.9f,\"gaps_gt100ms\":%llu,\"gaps_gt1s\":%llu,\"gaps_gt100ms_total_s\":%.6f,\"gaps_gt1s_total_s\":%.6f,\n",
        (unsigned long long)backwards,mindt<1e99?mindt:0,maxgap,maxbackward,(unsigned long long)gap100,(unsigned long long)gap1,gap100sum,gap1sum);
    printf("\"tcp_fixed_header_missing\":%llu,\"tcp_invalid_data_offset\":%llu,\"tcp_options_truncated\":%llu,\n\"ip_protocol_counts\":{",
        (unsigned long long)tcp_fixed_missing,(unsigned long long)tcp_invalid,(unsigned long long)tcp_options_cut);
    int comma=0;for(int i=0;i<256;i++)if(proto[i]){printf("%s\"%d\":%llu",comma?",":"",i,(unsigned long long)proto[i]);comma=1;}
    printf("}\n}\n");return 0;
}
