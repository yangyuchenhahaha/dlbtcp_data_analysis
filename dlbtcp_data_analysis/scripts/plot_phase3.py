#!/usr/bin/env python3
"""Render Chinese phase-3 descriptive event figures and three connection timelines.

Consumes summarize_phase3.py outputs, not the complete events file. Figures
describe observed packet events; user-deferred fast-path shares are not plotted.
"""
import argparse
from collections import defaultdict
import csv
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.python-packages'))
os.environ.setdefault('MPLCONFIGDIR', str(ROOT / '.mplconfig'))
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib import font_manager
from matplotlib.lines import Line2D
from matplotlib.ticker import PercentFormatter
import numpy as np

ENDPOINTS = ['150.74.240.107', '203.42.121.173', '203.42.117.47',
             '2001:fab8:1071:93ea:700:1a:3fc1:7e80', '202.249.10.115', '43.15.244.195']
LETTERS = dict(zip(ENDPOINTS, 'ABCDEF'))
COLORS = ['#0072B2', '#D55E00', '#009E73', '#CC79A7', '#E69F00', '#56B4E9', '#666666', '#A0A0A0']
TYPES = ['DATA', 'PURE_ACK', 'SYN', 'SYNACK', 'FIN', 'RST', 'OTHER', 'INVALID']
TYPE_LABELS = {'DATA': '数据', 'PURE_ACK': '无载荷 ACK', 'SYN': 'SYN', 'SYNACK': 'SYN+ACK',
               'FIN': 'FIN', 'RST': 'RST', 'OTHER': '其他', 'INVALID': '字段无效'}
SEQ = ['BASELINE', 'IN_ORDER', 'AHEAD_GAP', 'GAP_FILL', 'PREFIX_UNOBSERVED', 'DUP_FULL', 'OVERLAP_PARTIAL', 'INVALID', 'NA']
ACK = ['BASELINE', 'ADVANCE', 'REPEAT', 'WINDOW_UPDATE', 'SAME', 'BACKWARD', 'INVALID', 'NA']
EVENT_LABELS = {'NA': '不适用', 'BASELINE': '首个观测', 'IN_ORDER': '连续前沿接续', 'AHEAD_GAP': '历史缺口之后', 'GAP_FILL': '填补缺口',
                'PREFIX_UNOBSERVED': '前缀未见', 'DUP_FULL': '完整重叠', 'OVERLAP_PARTIAL': '部分重叠', 'INVALID': '无效',
                'ADVANCE': 'ACK 前进', 'REPEAT': '同确认号 ACK', 'WINDOW_UPDATE': '窗口更新', 'SAME': 'ACK 相同', 'BACKWARD': 'ACK 后退'}
COHORT_LABELS = {'all': '全部观测包', 'high_load': '高负载窗口', 'ordinary': '普通负载窗口',
                 'balanced_high': '均衡高负载', 'hotspot_window_union': '热点窗口全部包',
                 'hotspot_dominant_union': '热点主导连接包'}
NOTE = '六个选定端点的链路可见 TCP 包；包形态与序列关系是观测分类。快速路径统计按用户要求暂缓。'


def read_csv(path):
    with path.open(encoding='utf-8', newline='') as stream:
        return list(csv.DictReader(stream))


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(4 * 1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def configure_fonts():
    preferred = ['Noto Sans CJK SC', 'Source Han Sans SC', 'WenQuanYi Micro Hei', 'WenQuanYi Zen Hei',
                 'Noto Serif CJK SC', 'Microsoft YaHei', 'SimHei', 'Droid Sans Fallback']
    available = {font.name for font in font_manager.fontManager.ttflist}
    selected = next((name for name in preferred if name in available), None)
    if selected is None:
        # Font cache may predate package installation; inspect standard local
        # font paths and register a CJK font without a network dependency.
        candidates = []
        for base in [Path('/usr/share/fonts'), Path.home() / '.local/share/fonts', ROOT / 'fonts']:
            if base.exists():
                candidates.extend(p for p in base.rglob('*') if p.suffix.lower() in {'.ttf', '.ttc', '.otf'} and any(t in p.name.lower() for t in ['cjk', 'wqy', 'sourcehan', 'droidsansfallback']))
        for path in candidates:
            try:
                font_manager.fontManager.addfont(str(path))
                selected = font_manager.FontProperties(fname=str(path)).get_name()
                break
            except (OSError, RuntimeError):
                continue
    if selected is None:
        raise RuntimeError('No local CJK font found; install/register a Chinese font before plotting')
    plt.rcParams.update({'font.family': [selected, 'DejaVu Sans'], 'axes.unicode_minus': False,
                         'font.size': 10, 'axes.titlesize': 11, 'axes.labelsize': 10,
                         'pdf.fonttype': 42, 'ps.fonttype': 42, 'savefig.facecolor': 'white'})
    return selected


def save(fig, out_dir, name, outputs, caption):
    for suffix in ['png', 'pdf']:
        path = out_dir / f'{name}.{suffix}'
        fig.savefig(path, dpi=180, bbox_inches='tight', metadata={'Creator': 'scripts/plot_phase3.py'})
        outputs.append({'path': str(path.resolve()), 'bytes': path.stat().st_size, 'sha256': digest(path), 'caption': caption})
    plt.close(fig)


def packet_shapes(summary, events, out_dir, outputs):
    data = {(r['endpoint'], r['cohort'], r['event']): int(r['packets']) for r in events if r['dimension'] == 'packet_type'}
    den = {(r['endpoint'], r['cohort']): int(r['packets']) for r in summary}
    fig, axes = plt.subplots(2, 2, figsize=(12.5, 9.0), sharey=True)
    for ax, cohort in zip(axes.flat, ['all', 'high_load', 'ordinary', 'balanced_high']):
        bottom = np.zeros(len(ENDPOINTS))
        for event, color in zip(TYPES, COLORS):
            values = np.array([data.get((ep, cohort, event), 0) / den.get((ep, cohort), 1) if den.get((ep, cohort), 0) else 0 for ep in ENDPOINTS])
            ax.bar(np.arange(6), values, .68, bottom=bottom, color=color, label=TYPE_LABELS[event], linewidth=.3, edgecolor='white')
            bottom += values
        for i, ep in enumerate(ENDPOINTS):
            n = den.get((ep, cohort), 0)
            ax.text(i, 1.015 if n else .03, f'n={n:,}' if n else '无样本', ha='center', va='bottom', fontsize=8, rotation=0 if n else 90)
        ax.set_title(COHORT_LABELS[cohort], loc='left')
        ax.set_xticks(range(6), list('ABCDEF'))
        ax.set_ylim(0, 1.14)
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.set_yticks([0, .25, .5, .75, 1])
        ax.set_ylabel('该 cohort 包数占比')
        ax.grid(axis='y', alpha=.15)
    handles, labels = axes[0, 0].get_legend_handles_labels()
    fig.legend(handles, labels, loc='upper center', ncol=8, bbox_to_anchor=(.5, .975), fontsize=9)
    fig.suptitle('TCP 包形态：互斥分类与负载场景对照', y=1.015, fontsize=15)
    fig.text(.5, -.005, NOTE + '\n空 cohort 保留为空；不同 cohort 可能重叠。', ha='center', fontsize=9)
    fig.tight_layout(rect=(0, .03, 1, .94))
    save(fig, out_dir, '01_packet_shapes', outputs, 'Each packet receives one morphology type; denominator is the endpoint/cohort packet count. Empty cohorts are not imputed.')


def event_heatmaps(events, out_dir, outputs):
    lookup = {(r['endpoint'], r['cohort'], r['dimension'], r['event']): int(r['packets']) for r in events}
    fig, axes = plt.subplots(2, 2, figsize=(15, 9))
    for row, (dimension, labels, heading) in enumerate([('seq_event_given_payload', SEQ, '有 payload 包的序列关系'), ('ack_event_given_ack', ACK, '含 ACK 位包的确认关系')]):
        for col, cohort in enumerate(['all', 'hotspot_dominant_union']):
            a = []
            den = []
            for ep in ENDPOINTS:
                counts = [lookup.get((ep, cohort, dimension, k), 0) for k in labels]
                n = sum(counts)
                den.append(n)
                a.append([v / n if n else np.nan for v in counts])
            a = np.array(a)
            ax = axes[row, col]
            ax.imshow(np.ma.masked_invalid(a), aspect='auto', cmap='Blues', vmin=0, vmax=1)
            ax.set_xticks(range(len(labels)), [EVENT_LABELS[x] for x in labels], rotation=35, ha='right')
            ax.set_yticks(range(6), [f'{LETTERS[e]}  (n={n:,})' for e, n in zip(ENDPOINTS, den)])
            for i in range(a.shape[0]):
                for j in range(a.shape[1]):
                    value = a[i, j]
                    ax.text(j, i, '—' if math.isnan(value) else f'{value:.1%}', ha='center', va='center', fontsize=8, color='white' if value > .55 else '#222222')
            ax.set_title(f'{heading} · {COHORT_LABELS[cohort]}', loc='left')
    fig.suptitle('序列与 ACK 分类：分别使用有效 payload 包和含 ACK 位包为分母', fontsize=15)
    fig.text(.5, -.01, '每行按对应条件集合包数归一化。历史缺口可使后续相接数据持续带 AHEAD_GAP 标签，不能当作每包新乱序。\n重叠/缺口不确诊重传或网络故障；同确认号不等同完整重复 ACK 判据。', ha='center', fontsize=9)
    fig.tight_layout(rect=(0, .03, 1, .95))
    save(fig, out_dir, '02_sequence_ack_events', outputs, 'Sequence rows use valid payload-bearing packets, including SYN/FIN/RST payload. ACK rows use valid fixed fields with ACK bit. Repeated ACK values are not a full duplicate-ACK test; observed sequence relationships do not establish network faults.')


def context_chart(summary, events, out_dir, outputs):
    cohorts = ['all', 'ordinary', 'balanced_high', 'hotspot_window_union']
    lookup = {(r['endpoint'], r['cohort']): r for r in summary}
    fig, axes = plt.subplots(1, 2, figsize=(14, 5.5), gridspec_kw={'width_ratios': [1.2, 1]})
    for i, cohort in enumerate(cohorts):
        values = []
        for ep in ENDPOINTS:
            row = lookup.get((ep, cohort), {})
            values.append(float(row['uncertain_packet_fraction']) if row.get('uncertain_packet_fraction') else np.nan)
        axes[0].bar(np.arange(6) + (i - 1.5) * .19, values, .18, color=COLORS[i], label=COHORT_LABELS[cohort])
    axes[0].set_xticks(range(6), list('ABCDEF'))
    axes[0].set_ylim(0, 1.05)
    axes[0].yaxis.set_major_formatter(PercentFormatter(1))
    axes[0].set_ylabel('带至少一种不确定标记的包占比')
    axes[0].set_title('包含最终会话上下文的可见性边界', loc='left')
    axes[0].legend(fontsize=8, ncol=2)
    totals = defaultdict(int)
    for row in events:
        if row['cohort'] == 'all' and row['dimension'] == 'uncertainty' and row['event'] != 'NONE':
            totals[row['event']] += int(row['packets'])
    top = sorted(totals.items(), key=lambda kv: -kv[1])[:9]
    if top:
        axes[1].barh(range(len(top)), [n for _, n in top], color='#666666')
        axes[1].set_yticks(range(len(top)), [label for label, _ in top], fontsize=8)
        axes[1].invert_yaxis()
    axes[1].set_title('全部端点最常见的标记（可重叠）', loc='left')
    axes[1].set_xlabel('带该标记的包数')
    axes[1].ticklabel_format(axis='x', style='sci', scilimits=(0, 0))
    fig.text(.5, -.025, '单向可见、握手未确认或 ACK 未见等标记表示观测上下文不足；不证明实际抓包丢失或协议出错。', ha='center', fontsize=9)
    fig.tight_layout(rect=(0, .03, 1, 1))
    save(fig, out_dir, '03_observation_context', outputs, 'Reasons are non-exclusive, include final session context, and do not establish actual capture loss.')


def run_and_clustering(histogram, anomaly, out_dir, outputs):
    fig, axes = plt.subplots(1, 2, figsize=(13, 5.2))
    for ep, color in zip(ENDPOINTS, COLORS):
        rows = sorted([r for r in histogram if r['endpoint'] == ep and r['cohort'] == 'all'], key=lambda r: int(r['run_packets']))
        n = sum(int(r['runs']) for r in rows)
        if n:
            x = [int(r['run_packets']) for r in rows]
            y = np.cumsum([int(r['runs']) for r in rows]) / n
            axes[0].step(x, y, where='post', color=color, label=f'{LETTERS[ep]} (游程={n:,})')
    axes[0].set_xscale('log')
    axes[0].set_ylim(0, 1.02)
    axes[0].set_xlabel('同会话、同方向的正常事件连续包数')
    axes[0].set_ylabel('游程累计比例')
    axes[0].set_title('正常观测模式的连续性', loc='left')
    axes[0].legend(fontsize=8)
    lookup = {(r['endpoint'], r['cohort']): r for r in anomaly}
    width = .35
    for offset, field, label, color in [(-width / 2, 'adjacent_candidate_pairs', '实际相邻候选对', '#D55E00'),
                                        (width / 2, 'random_adjacent_expectation', '同流置换期望', '#0072B2')]:
        values = [float(lookup.get((ep, 'all'), {}).get(field, 0)) for ep in ENDPOINTS]
        axes[1].bar(np.arange(6) + offset, values, width, label=label, color=color)
    axes[1].set_xticks(range(6), list('ABCDEF'))
    axes[1].set_yscale('symlog', linthresh=1)
    axes[1].set_ylabel('相邻候选包对数（对称对数刻度）')
    axes[1].set_title('候选事件聚集：描述性对照', loc='left')
    axes[1].legend(fontsize=9)
    fig.text(.5, -.03, '严格连续前沿受历史未填缺口影响，游程与候选聚集也受此状态传播影响。正常模式不代表快速路径或可并行比例。\n置换期望 Σm(m−1)/n 不是显著性检验；候选不等于真实网络异常。', ha='center', fontsize=9)
    fig.tight_layout(rect=(0, .04, 1, 1))
    save(fig, out_dir, '04_event_continuity_clustering', outputs, 'Normal-pattern run CDF uses exact packet-run histograms. Candidate adjacency uses original directional stream adjacency against the fixed-n,m permutation expectation; no significance claim.')


def timeline_plots(input_dir, out_dir, outputs, max_points):
    path = input_dir / 'timeline_examples.json'
    if not path.exists():
        return
    specs = json.loads(path.read_text(encoding='utf-8'))
    data = defaultdict(list)
    packet_path = input_dir / 'timeline_packets.csv.gz'
    if packet_path.exists():
        with gzip.open(packet_path, 'rt', encoding='utf-8', newline='') as stream:
            for row in csv.DictReader(stream):
                data[row['example']].append(row)
    for spec in specs:
        rows = data[spec['example']]
        if not rows:
            continue
        start = float(spec['start_ts'])
        # Distinct session panels avoid comparing independent TCP sequence spaces.
        sessions = sorted({r['session_id'] for r in rows})
        bases = {}
        unwrapped_bases = {}
        for row in rows:
            seq = int(row['seq'])
            if 0 <= seq < 2 ** 32:
                bases.setdefault((row['session_id'], row['direction']), seq)
            if row.get('seq_unwrapped'):
                unwrapped_bases.setdefault((row['session_id'], row['direction']), int(row['seq_unwrapped']))

        def offset(row, field, direction):
            key = row['session_id'], direction
            field_unwrapped = field + '_unwrapped'
            if row.get(field_unwrapped) and key in unwrapped_bases:
                return (int(row[field_unwrapped]) - unwrapped_bases[key]) / 1024
            return ((int(row[field]) - bases[key] + 2 ** 31) % 2 ** 32 - 2 ** 31) / 1024
        fig, axes = plt.subplots(3, 1, figsize=(13, 9), sharex=True, gridspec_kw={'height_ratios': [1, 1, .65]})
        for ax, direction, color in zip(axes[:2], ['TX', 'RX'], COLORS[:2]):
            direction_rows = [r for r in rows if r['direction'] == direction]
            for sid in sessions:
                a = [r for r in direction_rows if r['session_id'] == sid]
                stride = max(1, math.ceil(len(a) / max_points))
                subset = a[::stride]
                seq_base = bases.get((sid, direction))
                ack_base = bases.get((sid, 'RX' if direction == 'TX' else 'TX'))
                if seq_base is not None:
                    valid = [r for r in subset if 0 <= int(r['seq']) < 2 ** 32]
                    ax.scatter([float(r['ts']) - start for r in valid], [offset(r, 'seq', direction) for r in valid], s=4, color=color, alpha=.6, rasterized=True)
                if ack_base is not None:
                    valid = [r for r in subset if int(r['flags']) >= 0 and int(r['flags']) & 16 and 0 <= int(r['ack']) < 2 ** 32]
                    ax.scatter([float(r['ts']) - start for r in valid], [offset(r, 'ack', 'RX' if direction == 'TX' else 'TX') for r in valid], s=5, marker='x', color='#777777', alpha=.5, rasterized=True)
            ax.set_ylabel(f'{direction} 序列 / ACK\n相对 KiB')
            ax.grid(alpha=.15)
            ax.legend(handles=[Line2D([], [], color=color, marker='.', linestyle='', label=f'{direction} SEQ（本方向基准）'),
                               Line2D([], [], color='#777777', marker='x', linestyle='', label='ACK（对方向基准）')], loc='upper left', fontsize=8)
        event_groups = [('DUP_FULL', '完整重叠', '#D55E00'), ('OVERLAP_PARTIAL', '部分重叠', '#CC79A7'),
                        ('AHEAD_GAP', '历史缺口之后', '#E69F00'), ('GAP_FILL', '填补缺口', '#009E73'),
                        ('PREFIX_UNOBSERVED', '前缀未见', '#56B4E9'), ('BACKWARD', 'ACK 后退', '#333333')]
        for i, (event, label, color) in enumerate(event_groups):
            a = [r for r in rows if r['seq_event'] == event or r['ack_event'] == event]
            stride = max(1, math.ceil(len(a) / max_points))
            axes[2].scatter([float(r['ts']) - start for r in a[::stride]], [i] * len(a[::stride]), s=10, color=color, marker='|', rasterized=True)
        axes[2].set_yticks(range(len(event_groups)), [x[1] for x in event_groups], fontsize=8)
        axes[2].set_ylim(-.6, len(event_groups) - .4)
        axes[2].set_xlabel('距所选时间段起点的秒数')
        axes[2].set_xlim(0, float(spec['end_ts']) - start)
        local = datetime.fromtimestamp(start, timezone(timedelta(hours=8))).isoformat()
        fig.suptitle(f'{spec["example"]} · 主导连接时间线\n{spec["connection"]}\n起点 {local}；{len(rows):,} 包，{len(sessions)} 个观测会话', fontsize=11)
        fig.text(.5, -.02, f'状态由完整输入历史建立；仅展示选定时段。SEQ/ACK 每方向至多 {max_points:,} 点，事件标记分别限同样数量；CSV 保留全部点。\n每个会话各方向以首个可见 SEQ 为基准；不表示真实初始序号。事件为可见序列关系。', ha='center', fontsize=9)
        fig.tight_layout(rect=(0, .04, 1, .91))
        save(fig, out_dir, f'05_timeline_{spec["example"]}', outputs, f'{spec["selection"]}; all selected timeline packets retained in CSV, plotted regular points thinned to {max_points} per session/direction; sequence offsets are local observed baselines.')


def plot(input_dir, out_dir, max_points=6000):
    out_dir.mkdir(parents=True, exist_ok=True)
    font = configure_fonts()
    summary = read_csv(input_dir / 'cohort_summary.csv')
    events = read_csv(input_dir / 'event_summary.csv')
    histogram = read_csv(input_dir / 'normal_run_histogram.csv')
    anomaly = read_csv(input_dir / 'anomaly_clustering.csv')
    outputs = []
    packet_shapes(summary, events, out_dir, outputs)
    event_heatmaps(events, out_dir, outputs)
    context_chart(summary, events, out_dir, outputs)
    run_and_clustering(histogram, anomaly, out_dir, outputs)
    timeline_plots(input_dir, out_dir, outputs, max_points)
    manifest = {'fast_path_status': 'deferred_by_user', 'font': font, 'endpoint_labels': LETTERS,
                'input_dir': str(input_dir.resolve()), 'outputs': outputs,
                'definitions': 'summary_manifest.json in input_dir; no fast-path or actual network-fault inference',
                'timeline_max_points_per_session_direction': max_points}
    (out_dir / 'figure_manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f'phase3 figures complete: {len(outputs)} PNG/PDF files; font {font}', file=sys.stderr)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-dir', type=Path, default=ROOT / 'report/phase3_mawi')
    parser.add_argument('--out-dir', type=Path, help='default: INPUT_DIR/figures')
    parser.add_argument('--max-points', type=int, default=6000)
    args = parser.parse_args()
    if args.max_points < 1:
        parser.error('--max-points must be positive')
    plot(args.input_dir, args.out_dir or args.input_dir / 'figures', args.max_points)


if __name__ == '__main__':
    main()
