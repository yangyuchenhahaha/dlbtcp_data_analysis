#!/usr/bin/env python3
"""Compare complete 10ms/100ms/1s bins using isolated fine 8-core simulations."""
import csv
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import sys
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.python-packages'))
os.environ.setdefault('MPLCONFIGDIR', str(ROOT / '.mplconfig'))
import numpy as np
import pandas as pd

BASE = ROOT / 'report/phase2_mawi'
OUT = BASE / 'window_granularity_20261021'
EPS = ['150.74.240.107', '203.42.121.173', '203.42.117.47',
       '2001:fab8:1071:93ea:700:1a:3fc1:7e80', '202.249.10.115', '43.15.244.195']
WIDTHS = [(0.01, '10ms'), (0.1, '100ms'), (1., '1s')]
FIELDS = ['window_index', 'start_ts', 'end_ts', 'packets', 'tx_packets', 'rx_packets',
          'wire_bytes', 'tx_wire_bytes', 'rx_wire_bytes', 'payload_bytes', 'active_connections',
          'top1_packets', 'top5_packets', 'top1_share', 'top5_share', 'top1_connection',
          'partial_boundary_window']
CORES = ['connection_bound_8', 'hash_8_imbalance', 'lpt_8_imbalance', 'hash_8_loads', 'lpt_8_loads']


def q(values, fraction):
    a = np.asarray(values)
    if not len(a):
        return None
    k = max(0, math.ceil(len(a) * fraction) - 1)
    return float(np.partition(a, k)[k])


def weighted(frame, field):
    total = int(frame['packets'].sum())
    return float(frame[field].sum() / total) if total else None


def record(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        while block := f.read(8 * 1024 * 1024):
            h.update(block)
    return dict(path=str(path.relative_to(ROOT)), bytes=path.stat().st_size, sha256=h.hexdigest())


def local(ts):
    return datetime.fromtimestamp(float(ts), ZoneInfo('Asia/Shanghai')).isoformat(timespec='milliseconds')


def segments(frame, label, ep, width, threshold):
    result, current = [], None
    for r in frame.itertuples(index=False):
        eligible = r.packets >= threshold and 2 * r.top1_packets >= r.packets
        continues = (eligible and current is not None and current['connection'] == r.top1_connection
                     and current['end_index'] == r.window_index)
        if current is not None and not continues:
            result.append(current)
            current = None
        if eligible:
            if current is None:
                current = dict(label=label, endpoint=ep, window_s=width, connection=r.top1_connection,
                               start_index=int(r.window_index), end_index=int(r.window_index),
                               start_ts=float(r.start_ts), end_ts=float(r.start_ts),
                               windows=0, endpoint_packets=0, dominant_packets=0)
            current['end_index'] = int(r.window_index) + 1
            current['end_ts'] = float(r.end_ts)
            current['windows'] += 1
            current['endpoint_packets'] += int(r.packets)
            current['dominant_packets'] += int(r.top1_packets)
    if current is not None:
        result.append(current)
    for r in result:
        r.update(duration_s=r['windows'] * width, start_local=local(r['start_ts']),
                 end_local=local(r['end_ts']), top1_share=r['dominant_packets'] / r['endpoint_packets'])
    return result


def write_csv(name, rows):
    with (OUT / name).open('w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def table(headers, rows):
    return '\n'.join([' | '.join(headers), *[' | '.join(map(str, r)) for r in rows]])


def plots(rows):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.ticker import PercentFormatter
    plt.rcParams.update({'font.family': ['Noto Sans CJK SC', 'DejaVu Sans'], 'font.size': 13,
                         'axes.unicode_minus': False, 'pdf.fonttype': 42,
                         'axes.spines.top': False, 'axes.spines.right': False})
    dest = OUT / 'figures'
    dest.mkdir(exist_ok=True)
    lookup = {(r['label'], r['window_s']): r for r in rows}
    for name, fields, titles, share in [
        ('01_concentration', ['top1_weighted_high', 'top5_weighted_high'],
         ['高负载窗 top1 包占比', '高负载窗 top5 包占比'], True),
        ('02_core8', ['lpt8_p50', 'hash8_p50'],
         ['8 核逐窗贪心分配失衡比 p50', '8 核固定哈希失衡比 p50（seed 0）'], False),
    ]:
        fig, axes = plt.subplots(1, 2, figsize=(14, 5.3))
        for ax, field, title in zip(axes, fields, titles):
            for i, ((width, grain), color) in enumerate(zip(WIDTHS, ['#0072B2', '#D55E00', '#009E73'])):
                ax.bar(np.arange(6) + (i - 1) * .25,
                       [lookup[label, width][field] for label in 'ABCDEF'],
                       width=.24, color=color, label=grain)
            ax.set_xticks(range(6), list('ABCDEF'))
            ax.set_title(title, pad=13)
            ax.grid(axis='y', alpha=.2)
            ax.set_axisbelow(True)
            if share:
                ax.yaxis.set_major_formatter(PercentFormatter(1))
                ax.set_ylim(0, 1.12)
            else:
                ax.set_ylim(0, 9)
                ax.axhline(1, linestyle=':', color='#555555', lw=1)
            ax.legend(ncol=3, fontsize=10, loc='upper left')
        note = ('各端点、各窗宽分别按完整窗 p90 且至少 20 包选高负载，并非同一批时段。'
                '\n占比按包数加权；短窗 top5 接近 100% 时须同时查看活跃连接数。' if share else
                '整条连接分配给一个核心，按包数模拟；10 ms / 100 ms 为本次补算。'
                '\n失衡比表示相对分配偏斜，不表示已测得 CPU 过载或吞吐下降。')
        fig.text(.5, .02, note, ha='center', fontsize=10)
        fig.tight_layout(rect=(0, .13, 1, 1))
        for suffix in ['png', 'pdf']:
            fig.savefig(dest / f'{name}.{suffix}', dpi=190, bbox_inches='tight')
        plt.close(fig)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    old = {(r['endpoint'], float(r['window_s'])): r
           for r in csv.DictReader((BASE / 'window_summary.csv').open())}
    endpoints = {r['endpoint']: r for r in csv.DictReader((BASE / 'endpoint_statistics.csv').open())}
    old_cores = {(r['endpoint'], float(r['window_s'])): r
                 for r in csv.DictReader((BASE / 'core_summary.csv').open()) if r['cores'] == '8'}
    results, all_segments, longest, paired, sources, checks = [], [], [], [], set(), 0
    for label, ep in zip('ABCDEF', EPS):
        original_dir = 'primary_windows' if label in 'ABC' else 'control_windows'
        new_dir = 'core_primary' if label in 'ABC' else 'core_control'
        for width, grain in WIDTHS:
            stem = ep.replace(':', '_')
            historical = BASE / original_dir / f'{stem}__{grain}.csv.gz'
            path = historical if width == 1 else OUT / new_dir / f'{stem}__{grain}.csv.gz'
            sources.update([historical, path])
            f = pd.read_csv(path, usecols=FIELDS + CORES)
            assert f['window_index'].is_unique
            assert bool((f['packets'] == f['tx_packets'] + f['rx_packets']).all())
            assert bool((f['wire_bytes'] == f['tx_wire_bytes'] + f['rx_wire_bytes']).all())
            assert int(f['packets'].sum()) == int(endpoints[ep]['packets'])
            assert int(f['wire_bytes'].sum()) == int(endpoints[ep]['wire_bytes'])
            checks += 5
            if width < 1:
                ref = pd.read_csv(historical, usecols=FIELDS)
                for field in FIELDS:
                    assert f[field].fillna('').equals(ref[field].fillna('')), (ep, grain, field)
                    checks += 1
            full = f[f['partial_boundary_window'] == 0].copy()
            threshold = max(20, int(q(full['packets'], .9)))
            high = full[full['packets'] >= threshold]
            nonempty = full[full['packets'] > 0]
            single = high['top1_packets'] * 2 >= high['packets']
            few = (high['top5_packets'] >= .8 * high['packets']) & (high['active_connections'] >= 10)
            balanced = ((high['active_connections'] >= 10) & (high['top1_packets'] <= .2 * high['packets'])
                        & (high['top5_packets'] <= .5 * high['packets']))
            ordinary = full[(full['packets'] > 0) & (full['packets'] >= q(full['packets'], .4))
                            & (full['packets'] <= q(full['packets'], .6))]
            for r in nonempty.itertuples(index=False):
                bound = max(1, 8 * r.top1_packets / r.packets)
                assert abs(bound - r.connection_bound_8) < 1e-10
                for policy in ['hash', 'lpt']:
                    loads = json.loads(getattr(r, f'{policy}_8_loads'))
                    imbalance = getattr(r, f'{policy}_8_imbalance')
                    assert len(loads) == 8 and min(loads) >= 0 and sum(loads) == r.packets
                    assert abs(imbalance - 8 * max(loads) / r.packets) < 1e-10
                    assert imbalance + 1e-10 >= bound
                checks += 7
            segs = segments(full, label, ep, width, threshold)
            all_segments.extend(segs)
            best = max(segs, key=lambda r: (r['windows'], r['endpoint_packets'])) if segs else None
            if best:
                longest.append({**best, 'tied_longest_segments': sum(r['windows'] == best['windows'] for r in segs)})
            row = dict(label=label, endpoint=ep, window_s=width, grain=grain, complete_windows=len(full),
                       nonempty_windows=len(nonempty), high_load_threshold_packets=threshold,
                       high_load_windows=len(high), high_load_fraction=len(high) / len(full),
                       high_packets=int(high['packets'].sum()), high_pps_p50=q(high['packets'] / width, .5),
                       high_record_MBps_p50=q(high['wire_bytes'] / width / 1e6, .5),
                       active_p50_high=q(high['active_connections'], .5),
                       top1_weighted_high=weighted(high, 'top1_packets'), top5_weighted_high=weighted(high, 'top5_packets'),
                       top1_p50_high=q(high['top1_share'], .5), single_hot_fraction_high=float(single.mean()),
                       few_hot_fraction_high=float(few.mean()), balanced_high_windows=int(balanced.sum()),
                       ordinary_windows=len(ordinary), ordinary_top1_weighted=weighted(ordinary, 'top1_packets'),
                       sparse_nonempty_fraction=float((nonempty['packets'] < 20).mean()),
                       empty_fraction=1 - len(nonempty) / len(full), bound8_p50=q(high['connection_bound_8'], .5),
                       lpt8_p50=q(high['lpt_8_imbalance'], .5), hash8_p50=q(high['hash_8_imbalance'], .5),
                       hash_avoidable_fraction=float(((high['hash_8_imbalance'] >= 1.5)
                                                     & (high['lpt_8_imbalance'] < 1.5)).mean()),
                       longest_single_hotspot_s=best['duration_s'] if best else 0, single_hotspot_segments=len(segs))
            for field in ['complete_windows', 'high_load_threshold_packets', 'high_load_windows', 'high_pps_p50',
                          'active_p50_high', 'top1_weighted_high', 'top5_weighted_high', 'top1_p50_high',
                          'single_hot_fraction_high', 'few_hot_fraction_high', 'sparse_nonempty_fraction']:
                assert abs(row[field] - float(old[ep, width][field])) < 1e-10, (ep, grain, field)
                checks += 1
            if width == 1:
                for field, target in [('bound_p50', 'bound8_p50'), ('lpt_p50', 'lpt8_p50'), ('hash0_p50', 'hash8_p50')]:
                    assert abs(float(old_cores[ep, width][field]) - row[target]) < 1e-10
                    checks += 1
            if label == 'A':
                # These three bins are nested inside the preselected 1s balanced sample.
                wanted = {1.: '1767157988.0', .1: '1767157988.8', .01: '1767157988.88'}[width]
                idx = int(round(float(wanted) / width))
                r = full[full['window_index'] == idx].iloc[0]
                paired.append(dict(label='A', grain=grain, start_local=local(r['start_ts']),
                                   end_local=local(r['end_ts']), packets=int(r['packets']),
                                   top1_packets=int(r['top1_packets']), top1_share=float(r['top1_share']),
                                   high_load=bool(r['packets'] >= threshold), bound8=float(r['connection_bound_8']),
                                   lpt8=float(r['lpt_8_imbalance']), hash8=float(r['hash_8_imbalance'])))
            results.append(row)
            print(f'{label} {grain}: top1={row["top1_weighted_high"]:.2%}, '
                  f'bound/LPT/hash={row["bound8_p50"]:.3f}/{row["lpt8_p50"]:.3f}/{row["hash8_p50"]:.3f}', flush=True)
    for name, rows in [('comparison.csv', results), ('single_hotspot_segments.csv', all_segments),
                       ('longest_single_hotspots.csv', longest), ('nested_A_example.csv', paired)]:
        write_csv(name, rows)
    plots(results)
    lookup = {(r['label'], r['window_s']): r for r in results}
    pct = lambda x: f'{x:.2%}'
    lines = [
        'MAWI 10 ms / 100 ms / 1 s 窗口粒度对比', '',
        '六端点10 ms与100 ms的8核固定哈希(seed 0)及逐窗贪心分配已补算，未改动历史结果或PPT。',
        '高负载按各端点各窗宽的全部完整窗(含空窗)包数p90且至少20包重算；各尺度不是同一批时段。', '',
        '主要观察',
        '1. 10 ms能看到更强的短时单连接集中，A/B/C比1 s更明显；活跃连接更少。',
        '2. 100 ms下C仍明显集中，top1/top5约65.66%/95.00%，集中不限于10 ms。',
        '3. 短窗top5接近100%时常伴随少于5条活跃连接，应结合top1解释。',
        '4. 8核模拟在细尺度仍有明显单连接不可拆分限制；A等端点还存在额外哈希分配损失。',
        '5. 一秒均衡不保证毫秒均衡：既定A均衡样本内，一个10 ms子窗top1为78.13%，8核失衡6.251。',
        '6. 最长持续高负载合格段受门槛和断段影响，不是完整连接寿命。', '',
        '高负载窗 top1 / top5 包占比（逐窗排名，按包数加权）',
        table(['端点', '10 ms', '100 ms', '1 s'],
              [[label, *[pct(lookup[label, w]['top1_weighted_high']) + ' / ' + pct(lookup[label, w]['top5_weighted_high'])
                          for w, _ in WIDTHS]] for label in 'ABCDEF']), '',
        '高负载窗活跃连接数 p50',
        table(['端点', '10 ms', '100 ms', '1 s'],
              [[label, *[int(lookup[label, w]['active_p50_high']) for w, _ in WIDTHS]] for label in 'ABCDEF']), '',
        '8核失衡比p50：单连接下界 / 贪心LPT / 固定哈希',
        table(['端点', '10 ms', '100 ms', '1 s'],
              [[label, *[' / '.join(f'{lookup[label, w][field]:.3f}' for field in
                                   ['bound8_p50', 'lpt8_p50', 'hash8_p50']) for w, _ in WIDTHS]]
               for label in 'ABCDEF']), '',
        '同一主导连接连续高负载且top1>=50%的最长合格段（秒）',
        table(['端点', '10 ms', '100 ms', '1 s'],
              [[label, *[f'{lookup[label, w]["longest_single_hotspot_s"]:.3f}' for w, _ in WIDTHS]]
               for label in 'ABCDEF']), '',
        '所有非空完整窗中少于20包的比例（分母不是高负载窗）',
        table(['端点', '10 ms', '100 ms', '1 s'],
              [[label, *[pct(lookup[label, w]['sparse_nonempty_fraction']) for w, _ in WIDTHS]]
               for label in 'ABCDEF']), '',
        '既定A均衡样本内的嵌套示例（所选较集中子窗，不代表所有细窗）',
        table(['窗宽', '起始北京时间', '包数', 'top1包数', 'top1占比', '8核下界/LPT/hash'],
              [[r['grain'], r['start_local'], r['packets'], r['top1_packets'], pct(r['top1_share']),
                f'{r["bound8"]:.3f}/{r["lpt8"]:.3f}/{r["hash8"]:.3f}'] for r in paired]), '',
        '解释边界',
        '- 各宽度分别取自身p90。不同高负载集合的变化不能全部归因于窗宽；嵌套例子单独控制了时段。',
        '- top1/top5是包数加权比例；不能乘8就当成逐窗下界的p50。前五身份可变化。',
        '- 少数连接热点还要求活跃连接>=10；短窗该比例低不等于单连接热点少。',
        '- 最长段要求同一主导身份、相邻完整合格窗；短暂跌破门槛会断段。E100ms有4个并列最长段。',
        '- 本次细尺度高负载门槛都高于20包；稀疏比例仍只描述所有非空窗，不能误读为高负载窗稀疏。',
        '- LPT的p50等于下界p50不代表每个窗都达到最优。模拟不代表真实RSS、CPU成本或吞吐。',
        '- 未重跑第三阶段事件分类；不把10ms/100ms负载结果说成相应事件比例已完成。', '',
        '汇报可用表述',
        '“10毫秒下，短时负载通常由更少连接承担；100毫秒下C依然明显集中。'
        '细粒度8核模拟仍存在单连接不可拆分限制，一秒均衡也不保证其内部毫秒均衡。'
        '但各尺度门槛和热点合并规则不同，持续时间需分别解释。”', '',
        '文件：comparison.csv、longest_single_hotspots.csv、single_hotspot_segments.csv、nested_A_example.csv、figures/。',
        '完整复现：bash scripts/run_phase2_granularity_comparison.sh',
        f'数值守恒及历史口径核对通过，检查数 {checks:,}；新细尺度窗口的基础负载字段与历史表逐列一致。',
    ]
    (OUT / 'report.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    sources.update([BASE / 'window_summary.csv', BASE / 'core_summary.csv', BASE / 'endpoint_statistics.csv',
                    Path(__file__), ROOT / 'scripts/phase2_endpoint_windows.py',
                    ROOT / 'scripts/run_phase2_granularity_comparison.sh',
                    OUT / 'core_primary/summary.json', OUT / 'core_control/summary.json'])
    metadata = dict(created_at_utc=datetime.now(timezone.utc).isoformat(), all_checks_passed=True,
                    checks=checks, widths_s=[w for w, _ in WIDTHS], core_counts=[8], hash_seed=0,
                    fine_simulation_recomputed=True, phase3_events_recomputed=False,
                    sources=[record(p) for p in sorted(sources)],
                    artifacts=[record(p) for p in sorted(OUT.glob('*')) if p.is_file() and p.name != 'validation.json']
                              + [record(p) for p in sorted((OUT / 'figures').glob('*'))])
    (OUT / 'validation.json').write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + '\n')
    print(f'Completed {len(results)} comparisons; {checks:,} checks passed; {OUT / "report.txt"}')


if __name__ == '__main__':
    main()
