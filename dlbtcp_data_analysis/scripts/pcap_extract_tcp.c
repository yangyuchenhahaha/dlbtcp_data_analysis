/* Extract outer TCP capture records from ordered, same-linktype input files.
 * Build: gcc -O3 -Wall pcap_extract_tcp.c -lpcap -o pcap_extract_tcp
 * Usage: pcap_extract_tcp output.pcap input0.pcap [input1.pcap ...]
 * Preserves capture bytes, original wire lengths and microsecond timestamps.
 */
#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
int main(int argc,char **argv){
    if(argc<3){fprintf(stderr,"usage: pcap_extract_tcp output.pcap inputs...\n");return 2;}
    char err[PCAP_ERRBUF_SIZE];pcap_dumper_t *out=NULL;int linktype=-1;uint64_t grand=0;
    for(int i=2;i<argc;i++){
        pcap_t *pc=pcap_open_offline(argv[i],err);if(!pc){fprintf(stderr,"%s\n",err);return 1;}
        int lt=pcap_datalink(pc);if(linktype<0){linktype=lt;out=pcap_dump_open(pc,argv[1]);if(!out){fprintf(stderr,"%s\n",pcap_geterr(pc));return 1;}}
        if(lt!=linktype){fprintf(stderr,"mixed linktypes unsupported\n");return 1;}
        struct bpf_program fp;if(pcap_compile(pc,&fp,"tcp",1,PCAP_NETMASK_UNKNOWN)<0){fprintf(stderr,"%s\n",pcap_geterr(pc));return 1;}
        struct pcap_pkthdr *h;const unsigned char *p;uint64_t seen=0,keep=0;int r;
        while((r=pcap_next_ex(pc,&h,&p))==1){seen++;if(pcap_offline_filter(&fp,h,p)){pcap_dump((unsigned char*)out,h,p);keep++;}}
        if(r==-1){fprintf(stderr,"%s\n",pcap_geterr(pc));return 1;}
        pcap_freecode(&fp);pcap_close(pc);grand+=keep;
        fprintf(stderr,"%s records=%llu tcp=%llu\n",argv[i],(unsigned long long)seen,(unsigned long long)keep);
    }
    if(pcap_dump_flush(out)!=0){fprintf(stderr,"flush failed\n");return 1;}
    pcap_dump_close(out);fprintf(stderr,"total TCP records=%llu\n",(unsigned long long)grand);return 0;
}
