/*
 * pcap2tsv_checked: local rebuild; original pcap2tsv.c is preserved.
 * Validates TCP data offsets, skips non-first IPv6 fragments, and fails on read errors.
 *
 * Emits one line per IPv4/IPv6 TCP (or optionally UDP) packet:
 *   ts_sec.usec  proto  src  dst  sport  dport  ip_len  tcp_payload_len
 *   flags  seq  ack  win  tcp_hdr_len  caplen  wirelen  opts_truncated
 *
 * - Handles Ethernet, 802.1Q VLAN, Linux SLL, and raw-IP link types
 *   (DLT_RAW/101/12, LINKTYPE_IPV4 228, LINKTYPE_IPV6 229; CAIDA uses raw IP).
 * - Nanosecond pcaps are read fine; libpcap scales timestamps to microseconds.
 * - Never dereferences beyond caplen; if the TCP header is cut,
 *   the packet is still emitted with tcp_hdr_len=-1 and hdr_incomplete=1.
 * - Build: gcc -O2 -o pcap2tsv pcap2tsv.c -lpcap
 * - Usage: pcap2tsv [-u] [-6] <file.pcap|-> > out.tsv
 *            -u  also emit UDP packets (payload_len from UDP length)
 *            -6  also emit IPv6 packets (addresses printed as hex groups)
 */
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

static int want_udp = 0, want_v6 = 0;
static uint64_t n_total = 0, n_emit = 0, n_nonip = 0, n_short = 0;

static inline uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static inline uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static void fmt_v4(uint32_t a, char *buf) {
    struct in_addr ia; ia.s_addr = htonl(a);
    strcpy(buf, inet_ntoa(ia));
}
static void fmt_v6(const uint8_t *a, char *buf) {
    inet_ntop(AF_INET6, a, buf, 64);
}

static void handle(const struct pcap_pkthdr *h, const uint8_t *pkt, int linktype) {
    n_total++;
    const uint8_t *p = pkt; uint32_t rem = h->caplen; uint16_t etype = 0;

    if (linktype == DLT_EN10MB) {
        if (rem < 14) { n_short++; return; }
        etype = rd16(p + 12); p += 14; rem -= 14;
        while (etype == 0x8100 || etype == 0x88a8) {
            if (rem < 4) { n_short++; return; }
            etype = rd16(p + 2); p += 4; rem -= 4;
        }
    } else if (linktype == DLT_RAW || linktype == 101 || linktype == 12 ||
               linktype == 228 /* LINKTYPE_IPV4 */ || linktype == 229 /* LINKTYPE_IPV6 */) {
        /* raw IP, no link header (CAIDA passive traces use this) */
        if (rem < 1) { n_short++; return; }
        etype = ((p[0] >> 4) == 6) ? 0x86dd : 0x0800;
    } else if (linktype == DLT_LINUX_SLL) {
        if (rem < 16) { n_short++; return; }
        etype = rd16(p + 14); p += 16; rem -= 16;
    } else { n_nonip++; return; }

    char s[64], d[64]; uint8_t proto; uint32_t ip_len, l4off; const uint8_t *l4;
    if (etype == 0x0800) {
        if (rem < 20) { n_short++; return; }
        uint8_t ihl = (p[0] & 0x0f) * 4;
        if (ihl < 20 || rem < ihl) { n_short++; return; }
        ip_len = rd16(p + 2); proto = p[9];
        uint16_t fragoff = rd16(p + 6) & 0x1fff;
        if (fragoff != 0) { n_nonip++; return; } /* non-first fragment: no L4 header */
        fmt_v4(rd32(p + 12), s); fmt_v4(rd32(p + 16), d);
        l4 = p + ihl; l4off = ihl; rem -= ihl;
        if (ip_len < ihl) ip_len = ihl; /* defensive */
        ip_len -= ihl; /* now = L4 length */
    } else if (etype == 0x86dd && want_v6) {
        if (rem < 40) { n_short++; return; }
        ip_len = rd16(p + 4); proto = p[6];
        fmt_v6(p + 8, s); fmt_v6(p + 24, d);
        l4 = p + 40; l4off = 40; rem -= 40;
        /* skip a few common extension headers */
        int guard = 8;
        while (guard-- && (proto == 0 || proto == 43 || proto == 60 || proto == 44)) {
            if (rem < 8) { n_short++; return; }
            if (proto == 44 && (rd16(l4 + 2) & 0xfff8) != 0) { n_nonip++; return; }
            uint8_t nxt = l4[0]; uint32_t xl = (proto == 44) ? 8 : (l4[1] + 1) * 8;
            if (rem < xl) { n_short++; return; }
            proto = nxt; l4 += xl; rem -= xl; ip_len = (ip_len >= xl) ? ip_len - xl : 0;
        }
    } else { n_nonip++; return; }

    if (proto == 6) {
        if (rem < 20) {
            n_emit++;
            printf("%ld.%06ld\t6\t%s\t%s\t-1\t-1\t%u\t-1\t-1\t0\t0\t0\t-1\t%u\t%u\t1\n",
                   (long)h->ts.tv_sec, (long)h->ts.tv_usec, s, d, ip_len, h->caplen, h->len);
            return;
        }
        uint16_t sp = rd16(l4), dp = rd16(l4 + 2);
        uint32_t seq = rd32(l4 + 4), ack = rd32(l4 + 8);
        uint8_t thl = (l4[12] >> 4) * 4; uint8_t flags = l4[13]; uint16_t win = rd16(l4 + 14);
        if (thl < 20 || thl > ip_len) {
            n_emit++;
            printf("%ld.%06ld\t6\t%s\t%s\t%u\t%u\t%u\t-1\t-1\t%u\t%u\t%u\t-1\t%u\t%u\t1\n",
                   (long)h->ts.tv_sec, (long)h->ts.tv_usec, s, d, sp, dp, ip_len, seq, ack, win, h->caplen, h->len);
            return;
        }
        int opts_trunc = (thl > 20 && rem < thl) ? 1 : 0;
        int32_t plen = (int32_t)ip_len - (int32_t)thl; if (plen < 0) plen = 0;
        n_emit++;
        printf("%ld.%06ld\t6\t%s\t%s\t%u\t%u\t%u\t%d\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%d\n",
               (long)h->ts.tv_sec, (long)h->ts.tv_usec, s, d, sp, dp, ip_len, plen,
               flags, seq, ack, win, thl, h->caplen, h->len, opts_trunc);
    } else if (proto == 17 && want_udp) {
        if (rem < 8) { n_short++; return; }
        uint16_t sp = rd16(l4), dp = rd16(l4 + 2), ul = rd16(l4 + 4);
        int32_t plen = (int32_t)ul - 8; if (plen < 0) plen = 0;
        n_emit++;
        printf("%ld.%06ld\t17\t%s\t%s\t%u\t%u\t%u\t%d\t0\t0\t0\t0\t8\t%u\t%u\t0\n",
               (long)h->ts.tv_sec, (long)h->ts.tv_usec, s, d, sp, dp, ip_len, plen,
               h->caplen, h->len);
    }
    (void)l4off;
}

int main(int argc, char **argv) {
    int ai = 1;
    for (; ai < argc && argv[ai][0] == '-' && argv[ai][1]; ai++) {
        if (!strcmp(argv[ai], "-u")) want_udp = 1;
        else if (!strcmp(argv[ai], "-6")) want_v6 = 1;
        else { fprintf(stderr, "unknown option %s\n", argv[ai]); return 2; }
    }
    if (ai >= argc) { fprintf(stderr, "usage: pcap2tsv [-u] [-6] <pcap|->\n"); return 2; }
    char err[PCAP_ERRBUF_SIZE];
    pcap_t *pc = pcap_open_offline(argv[ai], err);
    if (!pc) { fprintf(stderr, "pcap_open_offline: %s\n", err); return 1; }
    int lt = pcap_datalink(pc);
    struct pcap_pkthdr *h; const u_char *pkt; int r;
    static char obuf[1 << 20]; setvbuf(stdout, obuf, _IOFBF, sizeof obuf);
    while ((r = pcap_next_ex(pc, &h, &pkt)) == 1) handle(h, pkt, lt);
    if (r == -1) fprintf(stderr, "pcap read error: %s\n", pcap_geterr(pc));
    pcap_close(pc);
    fprintf(stderr, "linktype=%d total=%lu emitted=%lu non_ip_or_frag=%lu short=%lu\n",
            lt, (unsigned long)n_total, (unsigned long)n_emit, (unsigned long)n_nonip, (unsigned long)n_short);
    return r == -1 ? 1 : (ferror(stdout) ? 1 : 0);
}
