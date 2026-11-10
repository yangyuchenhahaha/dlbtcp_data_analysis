#!/usr/bin/env python3
"""Generate the two Chinese phase-3 reports from independently validated tables.

This does not classify events, select examples, or change classification rules.
It refuses a completion report when validation failed or its input hashes are
stale. Default outputs are phase3_report_20261018.md and README.md in the input
directory; all result statements and percentages come from the existing CSVs.
"""
import argparse
from collections import Counter
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENDPOINTS = ['150.74.240.107', '203.42.121.173', '203.42.117.47',
             '2001:fab8:1071:93ea:700:1a:3fc1:7e80', '202.249.10.115', '43.15.244.195']
LETTERS = dict(zip(ENDPOINTS, 'ABCDEF'))
COHORTS = [('all', '全部观测包'), ('hotspot_dominant_union', '热点主导连接包')]
SOURCE_FILES = ['classification_manifest.json', 'summary_manifest.json', 'cohort_summary.csv',
                'event_summary.csv', 'normal_runs.csv', 'anomaly_clustering.csv', 'timeline_examples.json', 'sessions.csv',
                'conditional_event_summary.csv']
REASONS = [('NO_INITIAL_SYN', '未见完整初始 SYN 上下文'), ('ONE_DIRECTION_ONLY', '片段单向可见'),
           ('ACK_UNOBSERVED', 'ACK 涉及未见序号'), ('TIMESTAMP_ORDER_SENSITIVE', '时间排序敏感'),
           ('OPTIONS_TRUNCATED', '选项截断')]


def read_csv(path):
    with path.open(encoding='utf-8', newline='') as handle:
        return list(csv.DictReader(handle))


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'))


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as handle:
        while block := handle.read(4 * 1024 * 1024):
            value.update(block)
    return value.hexdigest()


def indexed(rows, fields):
    answer = {}
    for row in rows:
        key = tuple(row[field] for field in fields)
        if key in answer:
            raise ValueError(f'duplicate table key: {key}')
        answer[key] = row
    return answer


def number(value):
    return None if value in ('', None) else float(value)


def integer(value):
    return int(value) if value not in ('', None) else 0


def fmt(value, decimals=0):
    value = number(value)
    return '—' if value is None else f'{value:,.{decimals}f}'


def pct(count, denominator):
    return f'{100 * float(count) / float(denominator):.2f}%' if denominator else '—'


def truth(value):
    return str(value).lower() in {'1', 'true', 'yes'}


def table(headers, rows):
    def cell(value):
        return str(value).replace('|', '\\|').replace('\n', ' ')
    lines = ['| ' + ' | '.join(map(cell, headers)) + ' |',
             '| ' + ' | '.join(['---'] * len(headers)) + ' |']
    lines += ['| ' + ' | '.join(map(cell, row)) + ' |' for row in rows]
    return '\n'.join(lines)


def relative(path, output_dir):
    return os.path.relpath(path.resolve(), output_dir.resolve()).replace(os.sep, '/')


def link(label, path, output_dir):
    return f'[{label}]({relative(path, output_dir)})'


def validate_inputs(directory):
    validation = read_json(directory / 'validation.json')
    if validation.get('all_checks_passed') is not True or validation.get('failures'):
        raise RuntimeError('Independent validation has not passed; refusing to write a completion report')
    if validation.get('independent_validation') is not True:
        raise RuntimeError('The report requires independent phase-3 validation')
    hashes = validation.get('input_sha256', {})
    normalized = {str(Path(name).resolve()): value for name, value in hashes.items()}
    for name in SOURCE_FILES:
        path = directory / name
        expected = normalized.get(str(path.resolve()))
        if expected is None or digest(path) != expected:
            raise RuntimeError(f'{name}: absent or stale validation hash; rerun validate_phase3_outputs.py')
    for name in ['classification_manifest.json', 'summary_manifest.json']:
        if read_json(directory / name).get('fast_path_status') != 'deferred_by_user':
            raise RuntimeError(f'{name}: fast-path status does not match the user-deferred scope')
    return validation


def generate(directory, output_dir):
    directory = directory.resolve()
    output_dir = output_dir.resolve()
    validation = validate_inputs(directory)
    classifier = read_json(directory / 'classification_manifest.json')
    summary_manifest = read_json(directory / 'summary_manifest.json')
    cohorts = indexed(read_csv(directory / 'cohort_summary.csv'), ['endpoint', 'cohort'])
    events = indexed(read_csv(directory / 'event_summary.csv'), ['endpoint', 'cohort', 'dimension', 'event'])
    runs = indexed(read_csv(directory / 'normal_runs.csv'), ['endpoint', 'cohort'])
    anomalies = indexed(read_csv(directory / 'anomaly_clustering.csv'), ['endpoint', 'cohort'])
    examples = read_json(directory / 'timeline_examples.json')
    sensitivity = read_json(directory / 'frontier_sensitivity.json')
    if (sensitivity.get('all_checks_passed') is not True
            or sensitivity.get('source_timeline_sha256') != validation['input_sha256'].get(str((directory / 'timeline_packets.csv.gz').resolve()))):
        raise RuntimeError('frontier sensitivity must match the validated representative timelines')
    raw_payload = Counter()
    with (directory / 'sessions.csv').open(encoding='utf-8', newline='') as handle:
        for row in csv.DictReader(handle):
            raw_payload[row['endpoint']] += integer(row['payload_bytes'])
    for ep in ENDPOINTS:
        for cohort in ['all', 'hotspot_dominant_union', 'ordinary', 'balanced_high']:
            if (ep, cohort) not in cohorts:
                raise ValueError(f'missing explicit endpoint/cohort row: {ep}/{cohort}')
    total = sum(integer(cohorts[ep, 'all']['packets']) for ep in ENDPOINTS)
    if total != integer(classifier['total_endpoint_packets']):
        raise ValueError('validated cohort/classifier total mismatch')
    output_dir.mkdir(parents=True, exist_ok=True)
    source_link = lambda name, label=None: link(label or name, directory / name, output_dir)

    def event_count(ep, cohort, dimension, event, measure='packets'):
        row = events.get((ep, cohort, dimension, event))
        return integer(row[measure]) if row else 0

    def shape_pct(ep, cohort, event):
        return pct(event_count(ep, cohort, 'packet_type', event), integer(cohorts[ep, cohort]['packets']))

    def event_pair(ep, cohort, dimension, event, prefix):
        c = cohorts[ep, cohort]
        n, wire = integer(c[prefix + 'packets']), integer(c[prefix + 'wire_bytes'])
        return pct(event_count(ep, cohort, dimension, event), n) + ' / ' + pct(event_count(ep, cohort, dimension, event, 'wire_bytes'), wire)

    packet_rows = []
    invalid_rows = []
    shape_rows = []
    for ep in ENDPOINTS:
        row = cohorts[ep, 'all']
        packet_rows.append([LETTERS[ep], ep, fmt(row['packets']), fmt(row['wire_bytes']), fmt(raw_payload[ep]), fmt(row['valid_payload_bytes'])])
        invalid_rows.append([LETTERS[ep], fmt(event_count(ep, 'all', 'packet_type', 'INVALID')),
                             fmt(event_count(ep, 'all', 'packet_type', 'INVALID', 'wire_bytes')),
                             fmt(raw_payload[ep] - integer(row['valid_payload_bytes']))])
        shape_rows.append([LETTERS[ep], fmt(row['packets']), shape_pct(ep, 'all', 'DATA'), shape_pct(ep, 'all', 'PURE_ACK'),
                           fmt(cohorts[ep, 'hotspot_dominant_union']['packets']),
                           shape_pct(ep, 'hotspot_dominant_union', 'DATA'), shape_pct(ep, 'hotspot_dominant_union', 'PURE_ACK')])
    seq_rows, ack_rows, run_rows, anomaly_rows, uncertainty_rows = [], [], [], [], []
    for cohort, cohort_label in COHORTS:
        for ep in ENDPOINTS:
            c = cohorts[ep, cohort]
            seq_rows.append([LETTERS[ep], cohort_label, fmt(c['payload_bearing_packets']), fmt(c['payload_bearing_wire_bytes']),
                             *[event_pair(ep, cohort, 'seq_event_given_payload', event, 'payload_bearing_')
                               for event in ['IN_ORDER', 'AHEAD_GAP', 'DUP_FULL', 'OVERLAP_PARTIAL']]])
            ack_rows.append([LETTERS[ep], cohort_label, fmt(c['ack_bearing_packets']), fmt(c['ack_bearing_wire_bytes']),
                             *[event_pair(ep, cohort, 'ack_event_given_ack', event, 'ack_bearing_')
                               for event in ['ADVANCE', 'REPEAT', 'WINDOW_UPDATE', 'BACKWARD']]])
            r = runs[ep, cohort]
            duration = number(r['duration_s_p90'])
            sample = integer(r['duration_s_quantile_sample_size'])
            count = integer(r['duration_s_count'])
            quantile_status = ('精确' if truth(r['duration_s_quantiles_exact']) else '近似') + f'（{sample:,}/{count:,}）' if count else '—'
            run_rows.append([LETTERS[ep], cohort_label, fmt(r['run_count']), fmt(r['run_packets_p50']), fmt(r['run_packets_p90']),
                             fmt(r['run_packets_max']), fmt(duration * 1000 if duration is not None else None, 3), quantile_status])
            a = anomalies[ep, cohort]
            interval = number(a['candidate_interval_s_p90'])
            interval_status = '' if truth(a['candidate_interval_s_quantiles_exact']) else '≈'
            anomaly_rows.append([LETTERS[ep], cohort_label, fmt(a['candidate_packets']),
                                 pct(integer(a['candidate_packets']), integer(a['packets'])), fmt(a['adjacent_candidate_pairs']),
                                 fmt(a['random_adjacent_expectation'], 2), fmt(a['observed_over_random_expectation'], 3),
                                 interval_status + fmt(interval * 1000 if interval is not None else None, 3)])
            uncertainty_rows.append([LETTERS[ep], cohort_label, pct(integer(c['uncertain_packets']), integer(c['packets'])),
                                     *[pct(event_count(ep, cohort, 'uncertainty', reason), integer(c['packets'])) for reason, _ in REASONS]])
    contrast_rows = []
    for ep in ENDPOINTS:
        contrast_rows.append([LETTERS[ep], fmt(cohorts[ep, 'ordinary']['packets']), shape_pct(ep, 'ordinary', 'DATA'),
                              shape_pct(ep, 'ordinary', 'PURE_ACK'), fmt(cohorts[ep, 'balanced_high']['packets']),
                              shape_pct(ep, 'balanced_high', 'DATA'), shape_pct(ep, 'balanced_high', 'PURE_ACK')])
    empty_ordinary = '、'.join(LETTERS[ep] for ep in ENDPOINTS if not integer(cohorts[ep, 'ordinary']['packets'])) or '无'
    empty_balanced = '、'.join(LETTERS[ep] for ep in ENDPOINTS if not integer(cohorts[ep, 'balanced_high']['packets'])) or '无'
    invalid = sum(event_count(ep, 'all', 'packet_type', 'INVALID') for ep in ENDPOINTS)
    total_uncertain = sum(integer(cohorts[ep, 'all']['uncertain_packets']) for ep in ENDPOINTS)
    reservoir = integer(summary_manifest['reservoir_size'])
    hot_shape = [(event_count(ep, 'hotspot_dominant_union', 'packet_type', 'DATA')
                  + event_count(ep, 'hotspot_dominant_union', 'packet_type', 'PURE_ACK'))
                 / integer(cohorts[ep, 'hotspot_dominant_union']['packets']) for ep in ENDPOINTS
                 if integer(cohorts[ep, 'hotspot_dominant_union']['packets'])]
    sensitivity_rows = [[r['example'], fmt(r['payload_packets']), fmt(r['strict_in_order_packets']),
                         fmt(r['adjacent_highwater_packets']) + '（' + pct(r['adjacent_highwater_packets'], r['payload_packets']) + '）',
                         fmt(r['new_forward_gap_packets']), fmt(r['unknown_previous_highwater_payload_packets'])]
                        for r in sensitivity['rows']]
    local_adjacency = [r['adjacent_highwater_fraction'] for r in sensitivity['rows'] if r['payload_packets']]
    lines = [
        '# MAWI 第三阶段：TCP 事件分类主体完成（快速路径依用户暂缓）',
        '',
        f'2026-10-18。本阶段已对第二阶段六个选定端点的 **{total:,} 个可见 TCP 包**完成事件分类、负载场景对照、正常事件游程及异常候选聚集描述。'
        f'独立校验通过 {integer(validation["checks_run"]):,} 项检查；数据来源与状态见 {source_link("validation.json")}。'
        '**用户明确要求暂不统计快速路径**；本报告不提供快速路径、可并行处理比例或实际 CPU 处理能力结论。',
        '',
        '## 主要观察',
        '',
        f'- 六个端点的热点主导连接中，DATA 与无载荷 ACK 的包数合计占 **{min(hot_shape):.2%}–{max(hot_shape):.2%}**。连接控制包占比较低，但包形态简单不等于序号关系可被完整核实。',
        f'- 严格历史连续前沿的缺口会向后传播标签；三条代表连接中，{min(local_adjacency):.2%}–{max(local_adjacency):.2%} 的 payload 包仍紧接已见最高尾部。因此高 AHEAD_GAP 比例不能解读为同等比例的新乱序或真实异常。',
        f'- 正常观测模式能形成较长游程，例如 E 的热点主导连接包中，每段游程的连续包数 p50 / p90 为 **{fmt(runs[ENDPOINTS[4], "hotspot_dominant_union"]["run_packets_p50"])} / {fmt(runs[ENDPOINTS[4], "hotspot_dominant_union"]["run_packets_p90"])}**；端点间差异较大，严格游程也受历史前沿及比较组边界影响。',
        '',
        '## 数据范围与分析方法',
        '',
        '输入沿用第二阶段主端点和对照端点的完整可见 TCP 历史，约为 2025-12-31 北京时间 13:00–13:15 的 MAWI 片段。'
        '每个端点维护独立双向状态，各方向分别跟踪序号区间、连续前沿与确认号；先按完整历史建立状态，再筛选热点窗口及主导连接包，避免把热点起点误当作连接初始化。'
        f'算法与限制以 {source_link("classification_rules.md", "分类规则")} 为准；不是 TCP 协议栈复现。',
        '',
        table(['标记', '端点', '全部包数', 'pcap 记录长度字节', '原始非负 payload 字节', '有效 payload 字节'], packet_rows),
        '',
        f'共生成 {integer(classifier["session_fragments"]):,} 个启发式会话片段。四元组复用提示与新 SYN/SYNACK 可触发片段切分，'
        '没有新 SYN 的复用仍可能无法识别，因此片段数及首末可见包时间不等于真实会话总数和完整会话寿命。',
        '',
        '全部包包括观察边界的部分窗口；负载场景采用第二阶段完整 1 秒窗口。高负载为该端点窗口包数达到自身 p90 且至少 20 包；'
        '单连接热点要求 top1≥50%，少数连接热点要求 top5≥80% 且活跃四元组至少 10。'
        '`hotspot_dominant_union` 为两类热点的主导连接包去重并集，不能与其他重叠 cohort 相加。'
        '它表示每窗选中的连接，主导身份可以随窗口变化。',
        '',
        'pcap 字节是原始记录长度，不额外添加链路开销；有效 payload 是头字段推断长度之和，不去重，不能称为 goodput。'
        '固定 TCP 字段无效的包保留为 INVALID，并排除有效 payload 与有效 ACK 条件分母。'
        '原始非负 payload 沿用阶段二/会话表对推断长度取 max(plen,0) 的口径；有效 payload 进一步排除 INVALID。'
        f'本次两者的总字节差额为 **{sum(raw_payload.values()) - sum(integer(cohorts[ep, "all"]["valid_payload_bytes"]) for ep in ENDPOINTS):,}**，'
        '无效/未知长度可能原本已被置零，因此存在 INVALID 包时两种字节总量仍可能相同。',
        '',
        '## 包形态及普通、均衡样本对照',
        '',
        '包形态采用互斥优先级 `INVALID → RST → SYNACK → SYN → FIN → DATA → PURE_ACK → OTHER`。'
        'DATA 为无上述控制标志且 payload>0 的包；PURE_ACK 为无 payload、ACK 置位且无 SYN/FIN/RST 的包，其名称不排除其他附加标志。'
        'SYN/FIN/RST 即使携带 payload，仍归控制形态，但继续独立记录 payload、序号及 ACK 行为。',
        '',
        table(['端点', '全部包数', 'DATA 包占比', 'PURE_ACK 包占比', '热点主导包数', 'DATA 包占比', 'PURE_ACK 包占比'], shape_rows),
        '',
        '除 DATA 与 PURE_ACK 外，所有 SYN/SYNACK/FIN/RST/OTHER/INVALID 仍保留在互斥形态全表。INVALID 的独立口径为：',
        '',
        table(['端点', 'INVALID 包数', 'INVALID pcap 字节', '原始 payload−有效 payload 字节'], invalid_rows),
        '',
        table(['端点', '普通包数', '普通 DATA', '普通 PURE_ACK', '均衡高负载包数', '均衡 DATA', '均衡 PURE_ACK'], contrast_rows),
        '',
        '普通组取完整窗包数 p40–p60 且非空；均衡高负载要求活跃连接≥10、top1≤20%、top5≤50%。'
        f'当前普通组无样本端点：**{empty_ordinary}**；均衡高负载无样本端点：**{empty_balanced}**。'
        '表内零包数明确表示无样本，其事件比例保留“—”，不补造样本。普通负载并不保证连接均衡。'
        f'互斥形态全表及按字节的比例见 {source_link("event_summary.csv")}；cohort 分母见 {source_link("cohort_summary.csv")}。',
        '',
        '## 有 payload 包的序号关系',
        '',
        '以下各事件格为“**包占比 / pcap 字节占比**”。包数分母是该端点/cohort 内所有有效 payload>0 的包，'
        '包括携带数据的 SYN/FIN/RST；字节分母为同一条件集合的 pcap 记录长度总和。'
        'IN_ORDER 表示从已见连续前沿接续；AHEAD_GAP 表示位于尚未闭合的历史连续前沿之后；DUP_FULL、OVERLAP_PARTIAL 分别表示 payload 范围完全或部分覆盖已见范围。',
        '',
        table(['端点', '比较组', 'payload 包分母', 'pcap 字节分母', 'IN_ORDER 包% / 字节%', 'AHEAD_GAP 包% / 字节%',
               'DUP_FULL 包% / 字节%', 'OVERLAP_PARTIAL 包% / 字节%'], seq_rows),
        '',
        '表中只摘取四类，未列出的 BASELINE、GAP_FILL、PREFIX_UNOBSERVED、INVALID/NA 仍保留在全表，所列比例无需合计为 100%。'
        'payload 序号范围重叠不证明内容相同；现有 TSV 没有 payload 内容或哈希，不能由重复范围直接确诊真实重传、网络乱序或网络丢包。'
        'SYN 与 FIN 消耗序号，ACK/RST 本身不消耗序号，序号区间处理依据 '
        '[RFC 9293 §3.4](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.4)。',
        '',
        f'准确条件行见 {source_link("event_summary.csv")} 的 `seq_event_given_payload`；'
        f'{source_link("conditional_event_summary.csv")} 同时提供 DATA、所有有效 payload 及 ACK 位三种条件分母和完整类别。',
        '',
        '### 历史缺口敏感性：不要把 AHEAD_GAP 当作新乱序率',
        '',
        '一个未填补的历史缺口会让连续前沿停留在原处，即使后续数据紧接最高已见尾部，也仍归 AHEAD_GAP。'
        '对三段既定代表连接做独立诊断，当前 payload 起点与上一同片段、同方向记录中的完整历史 highwater 比较，得到：',
        '',
        table(['代表连接', 'payload 包数', '严格 IN_ORDER 包数', '紧接已见最高尾部', '新增观测空档包数', '缺少前一highwater未判定'], sensitivity_rows),
        '',
        '这些结果仅针对所选单条连接，不包含同时存在的背景连接，也不能外推为六个端点总体。'
        '首个相关方向的记录没有前一 highwater 时保守记未判定。严格 IN_ORDER 很低与局部接续比例很高可以同时出现，'
        '二者统计的是“完整历史链恢复”和“局部相邻区间接续”两个问题。新增观测空档同样不能确诊网络丢包或乱序。'
        '因此严格游程及异常候选聚集还包含历史状态传播因素，不代表真实常规处理能力或独立异常密度。'
        f'诊断见 {source_link("frontier_sensitivity.csv")} 与 {source_link("frontier_sensitivity.json")}；不涉及快速路径统计。',
        '',
        '## 含 ACK 位包的确认关系',
        '',
        '以下仍为“**包占比 / pcap 字节占比**”，分母改为固定字段有效且 ACK 位置位的所有包，以及这些包对应的 pcap 字节总和。'
        'ADVANCE 为确认号相对本方向已见最大确认号推进；BACKWARD 为后退。'
        'REPEAT 仅表示同确认号、同原始窗口的无 payload ACK；WINDOW_UPDATE 为同确认号但原始窗口变化的无 payload ACK。',
        '',
        table(['端点', '比较组', 'ACK 包分母', 'pcap 字节分母', 'ADVANCE 包% / 字节%', 'REPEAT 包% / 字节%',
               'WINDOW_UPDATE 包% / 字节%', 'BACKWARD 包% / 字节%'], ack_rows),
        '',
        'ACK 值 0 仍是合法数值。BASELINE、SAME 等其他类别在全表保留。REPEAT 没有验证发送端 outstanding data 等完整条件，'
        '不能等同于 [RFC 5681 §2](https://www.rfc-editor.org/rfc/rfc5681.html#section-2) 的完整 duplicate ACK 判据；'
        '窗口变化也不证明该更新一定会被真实协议栈接受。'
        f'条件数据见 {source_link("event_summary.csv")} 的 `ack_event_given_ack` 和 {source_link("conditional_event_summary.csv")}。',
        '',
        '## 正常观测模式的连续性',
        '',
        '这里的正常观测模式仅用于游程描述：无 SYN/FIN/RST，并且有 payload 的包为 IN_ORDER，或 PURE_ACK 的确认号 ADVANCE。'
        '它不排除包带有上下文标记，不是快速路径类别。游程沿**同一会话片段、同一方向**的包序列统计；'
        '非正常模式包、片段变化、退出 cohort 或跳过一个及以上中间 cohort 秒窗会中断；其他连接的包不打断本连接。'
        '全部包组允许连接闲置，所选 1 秒 cohort 则不跨越缺少本方向包的中间秒窗。',
        '',
        table(['端点', '比较组', '游程数', '连续包数 p50', '连续包数 p90', '最大连续包数', '首末包跨度 p90（ms）', '跨度分位样本/总数'], run_rows),
        '',
        f'连续包数分位来自完整直方图，精确计算。持续时间字段指**首末包观察跨度**，即末包时间减首包时间，单包游程为 0；'
        '全部包组的跨度可能包含空闲间隔，不能当作 CPU 连续工作的时长。跨度分位采用固定种子、'
        f'容量 **{reservoir:,}** 的 reservoir，各行明确标注精确或近似及样本数/总数。'
        '游程可能被观察区间、片段和比较组边界截断/删失；模式允许上下文标记，并未确认这些包都可靠或可以并行。'
        f'完整结果及分位精确性字段见 {source_link("normal_runs.csv")}，精确连续包数直方图见 {source_link("normal_run_histogram.csv")}。',
        '',
        '## 异常候选的时间聚集',
        '',
        '异常候选定义为序号 AHEAD_GAP/GAP_FILL/PREFIX_UNOBSERVED/DUP_FULL/OVERLAP_PARTIAL、ACK BACKWARD，或 ACK_UNOBSERVED 标记。'
        'TIMESTAMP_ORDER_SENSITIVE 单独出现不会使一个包成为异常候选。候选比例仍以该 cohort 所有包为分母。'
        '相邻对要求候选在原同会话、同方向包序列中相邻，保留中间普通包；候选间隔则可以跨越中间普通包。',
        '',
        table(['端点', '比较组', '候选包数', '候选包占比', '观测相邻对', '条件随机期望', '观测/期望', '候选间隔 p90（ms）'], anomaly_rows),
        '',
        '条件随机参照在每个同流连续 cohort episode 内固定 n 个包、m 个候选，将候选标签随机置换，'
        '相邻候选对期望为 `m*(m-1)/n`，再对 episode 求和。表中的比值只描述相对于此参照的聚集程度，'
        '未进行显著性检验，不能直接宣称实际网络故障或因果关系。期望为零时比值保留为空。'
        'AHEAD_GAP 及 ACK_UNOBSERVED 可能反映持续未恢复的观察上下文，标签传播本身可形成成簇，不能将候选包数或聚集比值直接当作独立网络异常的数量或密度。'
        f'间隔分位同样采用容量 {reservoir:,} 的 reservoir，近似值标“≈”；样本数及精确性见 {source_link("anomaly_clustering.csv")}。'
        f'不同候选标签的相邻对计数见 {source_link("anomaly_adjacent_pairs.csv")}。',
        '',
        '## 不确定性与可识别范围',
        '',
        f'全部包中带至少一种不确定性或上下文标记的比例为 **{pct(total_uncertain, total)}**。'
        f'固定字段无效而归为 INVALID 的包数为 **{invalid:,}**。这两个统计口径不同：'
        '缺少握手、只见一个方向、短包间隔或选项截断不等于连 DATA/ACK 等形态也无法识别。',
        '',
        table(['端点', '比较组', '任一标记', *[label for _, label in REASONS]], uncertainty_rows),
        '',
        '上表五个具体原因依次对应 `NO_INITIAL_SYN`、`ONE_DIRECTION_ONLY`、`ACK_UNOBSERVED`、'
        '`TIMESTAMP_ORDER_SENSITIVE`、`OPTIONS_TRUNCATED`。',
        '',
        '各原因比例均以本组全部包为分母，可以重叠，不能相加得到总体比例。'
        '`ONE_DIRECTION_ONLY`、`TUPLE_REUSED`、`HANDSHAKE_NOT_CONFIRMED` 会补充最终片段上下文；在线的未见 SYN/握手等理由仍保留。'
        '`ACK_UNOBSERVED` 表示无法用对方向已见序号核对确认范围，不证明 ACK 错误或真实网络丢包。'
        f'全部原因和字节比例见 {source_link("event_summary.csv")} 的 `uncertainty` 维度。',
        '',
        '相邻片段包间隔不超过 **200 μs** 时保留 TIMESTAMP_ORDER_SENSITIVE，这是保守的排序敏感提示，'
        '不证明包真的被重排，也不替代原始接收端到达顺序。第二阶段输入已稳定排序，事件分类沿用该观察顺序。'
        '同片段超过 **60 s** 闲置引入上下文与序号轮次歧义；端点/连接空闲不等于全捕获停顿，不能直接当作 capture gap。'
        'OPTIONS_TRUNCATED 表示选项信息不足，固定字段仍可用；本阶段未重建 SACK 或所有 TCP 选项行为。',
        '',
        '## 三段代表连接时间线',
        '',
        '例子沿用第二阶段既定的热点和均衡窗口：D 最长单连接热点、A 均衡高负载窗口内 top1 连接、C 最长单连接热点。'
        '均衡例子的 top1 只是该窗口包数最多的连接，不表示该连接主导整个端点。选择未根据本阶段异常标签重新挑选。',
        '',
    ]
    example_rows = []
    for spec in examples:
        start = float(spec['start_ts'])
        end = float(spec['end_ts'])
        local = lambda ts: datetime.fromtimestamp(ts, timezone(timedelta(hours=8))).strftime('%Y-%m-%d %H:%M:%S')
        example_rows.append([spec['example'], LETTERS.get(spec['endpoint'], spec['endpoint']),
                             local(start) + '–' + local(end), fmt(end - start, 0) + ' s',
                             fmt(spec['observed_packets']), '`' + spec['connection'] + '`'])
    lines += [table(['例子', '端点', '北京时间（左闭右开）', '长度', '所选连接包数', '四元组'], example_rows), '',
              f'例子元数据见 {source_link("timeline_examples.json")}；全部代表包与最终背景标记保留于 {source_link("timeline_packets.csv.gz")}。'
              '图中分别展示 TX/RX 序列、对方向确认范围和候选事件。SEQ/ACK 采用各会话、各方向首个可见序号为基准，'
              '绘图可以限点但 CSV 不限点；不把首个可见序号称作真实初始序号。', '']
    figure_captions = {
        '01_packet_shapes': '包形态与普通/均衡负载对照',
        '02_sequence_ack_events': '有 payload 包及含 ACK 位包的条件事件分布',
        '03_observation_context': '不确定性与上下文标记',
        '04_event_continuity_clustering': '正常事件连续性与候选聚集描述',
    }
    figure_captions.update({f'05_timeline_{s["example"]}': f'{s["example"]} 连接时间线' for s in examples})
    figures_found = 0
    for name, caption in figure_captions.items():
        png, pdf = directory / 'figures' / (name + '.png'), directory / 'figures' / (name + '.pdf')
        if png.exists():
            lines += [f'![{caption}]({relative(png, output_dir)})', '']
            figures_found += 1
        if pdf.exists():
            lines += [link(caption + '（PDF）', pdf, output_dir), '']
    if not figures_found:
        lines += ['当前未检测到 PNG 图；按下述命令运行绘图后重新生成报告。', '']
    lines += [
        '## 验证、复现与结论边界', '',
        f'独立校验共通过 {integer(validation["checks_run"]):,} 项检查，覆盖端点包数/字节与第二阶段守恒、'
        '会话上下文、cohort 身份及分母、互斥类别与条件分布、代表时间线包数、游程与随机参照的结构和范围。'
        '它没有独立重读并重新分类全部事件，因此不把汇总一致性解释为所有 TCP 事件语义均已由独立算法证实。'
        f'校验详情见 {source_link("validation.json")}；产物散列见后续生成的 {source_link("analysis_manifest.json")}。', '',
        '从项目根目录完整复现：', '', '```bash', 'bash scripts/run_phase3_mawi.sh', '```', '',
        '从已生成的事件结果重做汇总、独立校验、绘图、报告和散列：', '', '```bash',
        'python3 scripts/summarize_phase3.py', 'python3 scripts/validate_phase3_outputs.py',
        'python3 scripts/phase3_frontier_sensitivity.py',
        'python3 scripts/plot_phase3.py', 'python3 scripts/report_phase3.py', 'python3 scripts/build_phase3_manifest.py', '```', '',
        '本次结论适用于六个目的性选择端点、约 15 分钟骨干链路可见 TCP 子集，不能外推为所有 MAWI 端点或服务器全部网卡负载。'
        '没有发送端/接收端协议栈状态、payload 内容及完整选项，序号重叠、缺口与 ACK 关系只能作观察性分类。'
        '本报告按真实表格分别描述包形态、条件序列关系与连续性，不预设正常事件一定占多数。'
        '**第三阶段主体已完成；快速路径定义与比例依用户要求暂缓**，不由正常游程推导可并行率。', '',
        f'分类依据：{source_link("classification_rules.md", "本地完整规则")}；'
        '[RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html)；[RFC 5681](https://www.rfc-editor.org/rfc/rfc5681.html)。', '',
    ]
    report_name = 'phase3_report_20261018.md'
    report = '\n'.join(lines)
    descriptions = [
        (report_name, '第三阶段中文结果、分母、代表时间线与限制'),
        ('classification_rules.md', '包形态、会话片段、序号/ACK分类及边界规则'),
        ('events.csv.gz', '全部逐包分类；按完整历史建立状态，再附加第二阶段 cohort 标签'),
        ('sessions.csv', '启发式会话片段及最终单向/握手/复用背景'),
        ('cohort_summary.csv', '端点×cohort总量、有效字段及三种条件集合分母'),
        ('event_summary.csv', '包形态、序号、ACK、原因与三个条件维度的包/字节统计'),
        ('conditional_event_summary.csv', '独立校验器整理的条件事件分布；明确包数与字节分母'),
        ('frontier_sensitivity.csv', '三条既定代表连接中严格连续前沿与最高已见尾部接续的敏感性比较'),
        ('frontier_sensitivity.json', '敏感性诊断来源散列、计数和适用范围；不外推为六端点总体'),
        ('normal_runs.csv', '同片段同方向正常观测模式游程；duration为首末包观察跨度，非CPU工作时长或快速路径比例'),
        ('normal_run_histogram.csv', '全部正常游程的精确连续包数直方图'),
        ('anomaly_clustering.csv', '候选占比、间隔分位、相邻对及条件随机参照'),
        ('anomaly_adjacent_pairs.csv', '原包序列中相邻候选事件的标签对计数'),
        ('timeline_examples.json', 'D热点、A均衡、C热点三段既定连接例子'),
        ('timeline_packets.csv.gz', '三段连接的全部选中逐包事件，图片限点不影响该文件'),
        ('classification_manifest.json', '分类输入、端点包数、参数和分类守恒检查'),
        ('summary_manifest.json', '分母、正常模式、聚集及 reservoir 精确性说明'),
        ('validation.json', '独立校验范围、检查数、失败列表及被校验文件散列'),
        ('figures/figure_manifest.json', '实际 PNG/PDF 图路径、图注与散列'),
        ('analysis_manifest.json', '最终来源、脚本和报告/图表产物散列，最后生成'),
    ]
    readme_rows = []
    for name, description in descriptions:
        path = output_dir / name if name == report_name else directory / name
        readme_rows.append([link(name, path, output_dir), description])
    readme = '\n'.join([
        '# 第三阶段产物：主体完成，快速路径依用户暂缓', '',
        f'2026-10-18；六个第二阶段选定端点，{total:,} 个可见 TCP 包。'
        f'独立校验通过 {integer(validation["checks_run"]):,} 项检查。'
        f'结果详见 [{report_name}]({report_name})。`fast_path_status=deferred_by_user`；没有快速路径或可并行处理比例。', '',
        '## 完整复现', '', '在项目根目录运行；脚本使用本地 `.python-packages` 及现有第二阶段输入：', '',
        '```bash', 'bash scripts/run_phase3_mawi.sh', '```', '',
        '只从已有 events/sessions 重做后续产物：', '', '```bash',
        'export PYTHONPATH="$PWD/.python-packages${PYTHONPATH:+:$PYTHONPATH}"',
        'export MPLCONFIGDIR="$PWD/.mplconfig"',
        'python3 scripts/summarize_phase3.py', 'python3 scripts/validate_phase3_outputs.py',
        'python3 scripts/phase3_frontier_sensitivity.py',
        'python3 scripts/plot_phase3.py', 'python3 scripts/report_phase3.py',
        'python3 scripts/build_phase3_manifest.py', '```', '',
        '报告生成器会确认独立校验通过且被校验输入的散列未变化，然后仅更新两份 Markdown 报告。'
        '如更改分类/汇总，应重新运行其后的校验、绘图、报告和 manifest。', '',
        '## 文件说明', '', table(['文件', '内容'], readme_rows), '',
        '## 使用边界', '',
        '先完整历史、后筛热点；比较组可重叠，不能相加。E 的普通组和 C/D/E/F 的均衡高负载组无样本，'
        '保留零包数与空比例。DATA 与携数据控制包的条件集合不同；序号关系按有效 payload 包统计，ACK 关系按有效 ACK 位包统计。', '',
        '“正常”仅表示可见包模式的游程；序号重叠不等于确诊重传。'
        '缺初始 SYN、单向可见、ACK 未见范围、200 μs 排序敏感或选项截断不证明真实丢包，也不使所有形态均不可识别。'
        '60 s 连接闲置不是 capture gap；会话切分是启发式。'
        '首末包观察跨度/候选间隔分位使用固定种子 reservoir，表中保留样本数与精确性；全部组的跨度可包含idle，边界可删失。', '',
    ])
    (output_dir / report_name).write_text(report, encoding='utf-8')
    (output_dir / 'README.md').write_text(readme, encoding='utf-8')
    print(f'phase3 reports: {output_dir / report_name}; {output_dir / "README.md"}; validation passed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-dir', type=Path, default=ROOT / 'report/phase3_mawi')
    parser.add_argument('--out-dir', type=Path, help='default: INPUT_DIR; writes only the report and README')
    args = parser.parse_args()
    generate(args.input_dir, args.out_dir or args.input_dir)


if __name__ == '__main__':
    main()
