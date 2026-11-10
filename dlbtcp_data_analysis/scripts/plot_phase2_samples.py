#!/usr/bin/env python3
"""Plot interval-ranked TX/RX packet loads from the three real MAWI samples.

Run from the project directory with the project's plotting dependencies:
  PYTHONPATH="$PWD/.python-packages" MPLCONFIGDIR="$PWD/.mplconfig" \
    python3 scripts/plot_phase2_samples.py

Each sample is ranked independently by its WHOLE-INTERVAL connection total.
That ranking is different from a packet-weighted statistic of per-window top K
connections.  Connections mean endpoint/local-port/peer-IP/peer-port tuples;
reused TCP sessions are not separated.  Packet rates use each sample's complete
interval, and byte rates use the original pcap packet length field.
"""
import argparse
from collections import defaultdict
import csv
from datetime import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault('MPLCONFIGDIR', str(ROOT / '.mplconfig'))
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
from matplotlib.ticker import PercentFormatter
import numpy as np

NAMES = ['hotspot', 'balanced', 'ordinary']
FIELDS = ['sample', 'endpoint', 'rank', 'local_port', 'peer', 'peer_port',
          'packets', 'tx_packets', 'rx_packets', 'packet_share',
          'wire_bytes', 'tx_wire_bytes', 'rx_wire_bytes']


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_sample(sample):
    source = Path(sample['path'])
    if not source.is_absolute():
        source = ROOT / source
    endpoint = sample['endpoint']
    start, end = sample['start_ts'], sample['end_ts']
    connections = defaultdict(lambda: [0, 0, 0, 0])
    rows = 0
    with gzip.open(source, 'rt') as f:
        for line in f:
            fields = line.rstrip('\n').split('\t')
            if len(fields) != 16 or fields[1] != '6':
                raise ValueError(f'{source}: expected a 16-column TCP row')
            timestamp = float(fields[0])
            if not start <= timestamp < end:
                raise ValueError(f'{source}: row outside the requested half-open interval')
            src, dst, sport, dport = fields[2], fields[3], int(fields[4]), int(fields[5])
            if src == endpoint:
                conn, sending = (sport, dst, dport), True
            elif dst == endpoint:
                conn, sending = (dport, src, sport), False
            else:
                raise ValueError(f'{source}: packet is unrelated to {endpoint}')
            wire = int(fields[14])
            if wire < 0:
                raise ValueError(f'{source}: unknown original packet length')
            counts = connections[conn]
            counts[0 if sending else 1] += 1
            counts[2 if sending else 3] += wire
            rows += 1
    ranked = sorted(connections.items(), key=lambda item: (-sum(item[1][:2]), item[0]))
    result = []
    for rank, (conn, counts) in enumerate(ranked, 1):
        result.append(dict(sample=sample['name'], endpoint=endpoint, rank=rank,
                           local_port=conn[0], peer=conn[1], peer_port=conn[2],
                           packets=sum(counts[:2]), tx_packets=counts[0], rx_packets=counts[1],
                           packet_share=sum(counts[:2]) / rows,
                           wire_bytes=sum(counts[2:]), tx_wire_bytes=counts[2], rx_wire_bytes=counts[3]))
    packet_sum = sum(row['packets'] for row in result)
    byte_sum = sum(row['wire_bytes'] for row in result)
    if packet_sum != rows or rows != sample['endpoint_packets'] or byte_sum != sample['wire_bytes']:
        raise AssertionError(f'{source}: packet/byte counts disagree with the representative-sample metadata')
    duration = end - start
    info = dict(sample=sample['name'], endpoint=endpoint,
                source=str(source.resolve()), source_bytes=source.stat().st_size, source_sha256=sha256(source),
                start_ts=start, end_ts=end, duration_s=duration,
                start_beijing=datetime.fromtimestamp(start, ZoneInfo('Asia/Shanghai')).isoformat(),
                end_beijing=datetime.fromtimestamp(end, ZoneInfo('Asia/Shanghai')).isoformat(),
                packets=rows, tx_packets=sum(row['tx_packets'] for row in result),
                rx_packets=sum(row['rx_packets'] for row in result), wire_bytes=byte_sum,
                mean_pps=rows / duration, recorded_packet_mbps=byte_sum * 8 / duration / 1e6,
                connections=len(result),
                bidirectional_connections=sum(bool(row['tx_packets'] and row['rx_packets']) for row in result),
                top1_share_whole_interval=result[0]['packet_share'],
                top5_share_whole_interval=sum(row['packet_share'] for row in result[:5]),
                reference_per_window_top1_weighted=sample['top1_weighted'],
                reference_per_window_top5_weighted=sample['top5_weighted'])
    return result, info


def draw(ranked, statistics, out_dir, top):
    fig, axes = plt.subplots(3, 1, figsize=(13.5, 16), sharex=True)
    tx_color, rx_color = '#D55E00', '#0072B2'
    for ax, name in zip(axes, NAMES):
        info, rows = statistics[name], ranked[name]
        shown = rows[:top]
        remaining = rows[top:]
        if remaining:
            shown = shown + [dict(rank='other', packets=sum(row['packets'] for row in remaining),
                                 tx_packets=sum(row['tx_packets'] for row in remaining),
                                 rx_packets=sum(row['rx_packets'] for row in remaining))]
        if sum(row['packets'] for row in shown) != info['packets']:
            raise AssertionError('Top connections plus Other do not conserve sample packets')
        labels = [f'Rank {row["rank"]}' if row['rank'] != 'other'
                  else f'Other ({len(remaining)} connections)' for row in shown]
        tx = np.array([row['tx_packets'] for row in shown]) / info['packets']
        rx = np.array([row['rx_packets'] for row in shown]) / info['packets']
        y = np.arange(len(shown))
        ax.barh(y, tx, color=tx_color, height=.67)
        ax.barh(y, rx, left=tx, color=rx_color, height=.67)
        for j, row in enumerate(shown):
            share = row['packets'] / info['packets']
            text = f'{row["packets"]:,} packets ({share * 100:.2f}%)'
            if share > .82:
                ax.text(share - .01, j, text, ha='right', va='center', color='white', fontsize=8.5)
            else:
                ax.text(share + .008, j, text, ha='left', va='center', fontsize=8.5)
        ax.set_yticks(y, labels)
        ax.invert_yaxis()
        ax.set_xlim(0, 1.06)
        ax.set_xticks(np.linspace(0, 1, 6))
        ax.xaxis.set_major_formatter(PercentFormatter(1))
        ax.grid(axis='x', alpha=.15)
        ax.set_axisbelow(True)
        ax.set_ylabel('Observed connection rank', labelpad=12)
        start = datetime.fromisoformat(info['start_beijing'])
        end = datetime.fromisoformat(info['end_beijing'])
        interval = f'Beijing {start:%Y-%m-%d %H:%M:%S} - {end:%H:%M:%S} ({info["duration_s"]:g} s)'
        load = (f'{info["packets"]:,} packets | {info["mean_pps"]:,.1f} packets/s | '
                f'{info["recorded_packet_mbps"]:.2f} Mbit/s from pcap lengths | '
                f'{info["connections"]} connections')
        concentration = (f'Whole-interval ranking: Top 1 = {info["top1_share_whole_interval"]:.2%}, '
                         f'Top 5 = {info["top5_share_whole_interval"]:.2%}')
        ax.set_title(f'{name.upper()}  |  Endpoint {info["endpoint"]}\n{interval}\n{load}\n{concentration}',
                     loc='left', fontsize=10, pad=11)
    axes[-1].set_xlabel('Share of all endpoint packets in the sample interval (both directions)')
    fig.suptitle('Real endpoint samples: packet load per observed connection', fontsize=14, y=.994)
    fig.legend(handles=[Patch(color=tx_color, label='TX: endpoint sends'),
                        Patch(color=rx_color, label='RX: endpoint receives')],
               loc='lower center', ncol=2, bbox_to_anchor=(.5, .042), fontsize=10)
    fig.text(.5, .025, f'Top {top} connections plus all remaining connections. '
             'Ranked separately over each whole sample interval.', ha='center', fontsize=8.5)
    fig.text(.5, .011, 'Whole-interval Top K is not the packet-weighted statistic of per-window Top K. '
             'Observed link traffic; CPU work is not measured.', ha='center', fontsize=8)
    fig.tight_layout(rect=(0, .075, 1, .98), h_pad=2.4)
    paths = []
    for suffix in ['png', 'pdf']:
        path = out_dir / f'05_representative_connection_loads.{suffix}'
        fig.savefig(path, dpi=180, bbox_inches='tight', metadata={'Creator': 'scripts/plot_phase2_samples.py'})
        paths.append(path)
    plt.close(fig)
    return paths


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--report-dir', type=Path, default=ROOT / 'report/phase2_mawi')
    parser.add_argument('--out-dir', type=Path)
    parser.add_argument('--top', type=int, default=12)
    args = parser.parse_args()
    if args.top < 1:
        parser.error('--top must be positive')
    out_dir = args.out_dir or args.report_dir / 'figures'
    out_dir.mkdir(parents=True, exist_ok=True)
    samples_path = args.report_dir / 'representative_samples.json'
    samples = {row['name']: row for row in json.loads(samples_path.read_text())}
    if set(NAMES) - set(samples):
        raise ValueError('Missing real hotspot, balanced, or ordinary sample metadata')
    ranked, statistics = {}, {}
    for name in NAMES:
        ranked[name], statistics[name] = read_sample(samples[name])
    csv_path = out_dir / 'representative_connection_ranking.csv'
    with csv_path.open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        for name in NAMES:
            writer.writerows(ranked[name])
    stats_path = out_dir / 'representative_connection_statistics.json'
    stats_path.write_text(json.dumps(statistics, ensure_ascii=False, indent=2) + '\n')
    plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 9,
                         'axes.spines.top': False, 'axes.spines.right': False,
                         'pdf.fonttype': 42, 'savefig.facecolor': 'white'})
    figures = draw(ranked, statistics, out_dir, args.top)
    inputs = [dict(path=str(samples_path.resolve()), bytes=samples_path.stat().st_size, sha256=sha256(samples_path))]
    inputs += [dict(path=statistics[name]['source'], bytes=statistics[name]['source_bytes'],
                    sha256=statistics[name]['source_sha256']) for name in NAMES]
    outputs = [dict(path=str(p.resolve()), bytes=p.stat().st_size, sha256=sha256(p))
               for p in [*figures, csv_path, stats_path]]
    manifest = dict(script=str(Path(__file__).resolve()), inputs=inputs, outputs=outputs,
                    samples=statistics,
                    methodology=dict(connection='endpoint/local-port/peer-IP/peer-port observed tuple, not separated TCP sessions',
                                     ranking='Independent whole-interval total packets for each sample',
                                     plotted=f'TX/RX stacked packet shares for top{args.top} plus all other connections',
                                     rates='Interval packet count / interval seconds; pcap original packet lengths *8 / seconds /1e6',
                                     difference='Whole-interval top K can differ from per-window packet-weighted top K',
                                     timestamp_zone='Asia/Shanghai (UTC+08:00)',
                                     inference_limit='Observed monitored-link packet load, not complete server traffic or measured CPU costs'),
                    validation=dict(packet_counts_match_metadata=True, wire_bytes_match_metadata=True,
                                    direction_counts_conserve_packets=True, source_intervals_half_open=True))
    manifest_path = out_dir / 'sample_figure_manifest.json'
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(dict(manifest=str(manifest_path), samples=statistics), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
