#!/usr/bin/env bash
# Phase-1 inspection of a pcap: capture range, link type, snaplen/truncation,
# TCP field availability, direction symmetry, sampling hints.
# Usage: phase1_inspect.sh <pcap> [sample_packets]
set -u
P="$1"; N="${2:-2000000}"
echo "===== capinfos: $P ====="
capinfos -t -E -c -s -d -u -a -e -y -i -z "$P" 2>&1 | grep -vE "^$"
echo
echo "===== protocol hierarchy (first $N pkts) ====="
tshark -r "$P" -c "$N" -q -z io,phs 2>/dev/null | grep -E "^(eth|ip|ipv6|tcp|udp|arp|icmp|vlan| )" | head -25
echo
echo "===== per-packet caplen vs len (truncation check) ====="
tshark -r "$P" -c "$N" -T fields -e frame.cap_len -e frame.len 2>/dev/null \
  | awk '{n++; if($1<$2) t++; if($1>mx) mx=$1} END{printf "pkts=%d truncated=%d (%.1f%%) max_caplen=%d\n", n, t, 100*t/n, mx}'
echo
echo "===== TCP field presence (first $N pkts, tcp only) ====="
tshark -r "$P" -c "$N" -Y tcp -o tcp.relative_sequence_numbers:FALSE -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
  -e tcp.seq -e tcp.ack -e tcp.flags -e tcp.len -e tcp.window_size_value -e tcp.options.timestamp.tsval -e tcp.analysis.flags 2>/dev/null \
  | awk -F'\t' 'BEGIN{OFS="\t"} {n++; if($1!="")ts++; if($2!="")ip++; if($4!="")port++; if($6!="")seq++; if($7!="")ack++; if($8!="")fl++; if($9!="")len++; if($10!="")win++; if($11!="")tso++; if($9==0)pure++; if($12!="")an++}
  END{printf "tcp_pkts=%d ts=%d ip=%d port=%d seq=%d ack=%d flags=%d len=%d win=%d tsopt=%d zero_len=%d analysis_flagged=%d\n",n,ts,ip,port,seq,ack,fl,len,win,tso,pure,an}'
echo
echo "===== timestamp resolution: fraction digits & min positive delta ====="
tshark -r "$P" -c "$N" -T fields -e frame.time_epoch 2>/dev/null | awk 'NR>1{d=$1-p; if(d>0 && (mn==""||d<mn)) mn=d} {p=$1} END{printf "min_positive_delta=%.9f s\n", mn}'
tshark -r "$P" -c 20 -T fields -e frame.time_epoch 2>/dev/null | head -5
echo
echo "===== direction symmetry: for top 10 IP pairs, pkts each way ====="
tshark -r "$P" -c "$N" -Y tcp -T fields -e ip.src -e ip.dst 2>/dev/null \
  | awk '{a=$1; b=$2; if(a>b){t=a;a=b;b=t; dir="rev"} else dir="fwd"; k=a" "b; c[k]++; if(dir=="fwd") f[k]++; else r[k]++}
  END{for(k in c) printf "%d\t%d\t%d\t%s\n", c[k], f[k]+0, r[k]+0, k}' | sort -nr | head -10
echo
echo "===== top 10 IPs by packets (as src or dst) ====="
tshark -r "$P" -c "$N" -Y tcp -T fields -e ip.src -e ip.dst 2>/dev/null | tr '\t' '\n' | sort | uniq -c | sort -nr | head -10
