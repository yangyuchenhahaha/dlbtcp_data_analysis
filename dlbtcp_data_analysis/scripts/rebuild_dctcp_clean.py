#!/usr/bin/env python3
"""Rebuild clean DCTCP summaries and verify the original per-flow artifacts.

Run after phase1_dctcp_dataset.py. Input data is an explicitly verified Zenodo
10894768 archive. No assumptions about pure ACKs, wire packets, or congestion
causes are made: measurements remain TCP socket segment counters.
"""
from pathlib import Path
import argparse
import hashlib
import json
import numpy as np
import pandas as pd

ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('raw_root', type=Path)
ap.add_argument('rebuilt_dir', type=Path)
ap.add_argument('--archived-dir', type=Path)
a = ap.parse_args()
out = a.rebuilt_dir
flows = pd.read_csv(out / 'dctcp_per_flow.csv')
intervals = pd.read_csv(out / 'dctcp_intervals.csv.gz')
bad_mask = (flows.rows > 4000) | (flows.segs_out < 0) | (flows.segs_in < 0)
bad_keys = set(map(tuple, flows.loc[bad_mask, ['cca', 'run']].to_numpy()))
clean = flows.loc[~bad_mask].copy()
iv = intervals.loc[[tuple(k) not in bad_keys for k in intervals[['cca', 'run']].to_numpy()]].copy()
iv = iv.loc[iv.dt > 0].copy()
iv['host_total_pps'] = iv.data_pps_out + iv.segs_pps_in
iv.loc[iv.data_pps_out == 0].to_csv(out / 'dctcp_zero_data_intervals.csv', index=False)
extreme = pd.concat([iv.nlargest(100, metric).assign(selected_by=metric)
                     for metric in ['data_pps_out', 'segs_pps_in', 'host_total_pps']], ignore_index=True)
extreme.to_csv(out / 'dctcp_extreme_intervals.csv', index=False)
flow_quantiles = iv.groupby(['cca', 'run'])[['data_pps_out', 'segs_pps_in', 'host_total_pps', 'dt', 'rtt', 'cwnd']].quantile([0, .01, .5, .9, .99, 1])
flow_quantiles.index.names = ['cca', 'run', 'quantile']
flow_quantiles.to_csv(out / 'dctcp_per_flow_interval_quantiles.csv')
clean['host_total_pps_mean'] = clean.data_pps_out_mean + clean.segs_pps_in_mean
clean['incoming_segment_fraction'] = clean.segs_in / (clean.segs_out + clean.segs_in)
clean['data_segments_per_incoming_segment'] = clean.data_segs_out / clean.segs_in
clean.to_csv(out / 'dctcp_per_flow_clean.csv', index=False)
iv.to_csv(out / 'dctcp_intervals_clean.csv.gz', index=False)

integrity = []
counters = ['bytes_sent', 'bytes_retrans', 'bytes_acked', 'segs_out', 'segs_in', 'data_segs_out', 'delivered']
for idx, path in enumerate(sorted(a.raw_root.glob('*/*.csv'))):
    raw = pd.read_csv(path, sep=';').dropna(axis=1, how='all')
    missing_retrans = 'bytes_retrans' not in raw.columns
    if missing_retrans:
        raw['bytes_retrans'] = 0
    dt_ms = raw.lastrcv.diff().iloc[1:]
    row = {'cca': path.parent.name, 'run': path.name, 'rows': len(raw),
           'excluded_historical_rule': (path.parent.name, path.name) in bad_keys,
           'missing_bytes_retrans_filled_zero': missing_retrans,
           'first_lastrcv_ms': float(raw.lastrcv.iloc[0]), 'last_lastrcv_ms': float(raw.lastrcv.iloc[-1]),
           'negative_dt_intervals': int((dt_ms < 0).sum()), 'zero_dt_intervals': int((dt_ms == 0).sum()),
           'min_positive_dt_ms': float(dt_ms[dt_ms > 0].min()), 'max_positive_dt_ms': float(dt_ms.max())}
    for c in counters:
        v = raw[c]
        row[c + '_first'] = float(v.iloc[0])
        row[c + '_last'] = float(v.iloc[-1])
        row[c + '_negative_intervals'] = int((v.diff().iloc[1:] < 0).sum())
        row[c + '_missing_cells'] = int(v.isna().sum())
    integrity.append(row)
audit = pd.DataFrame(integrity)
audit.to_csv(out / 'dctcp_flow_integrity.csv', index=False)

agg = clean.groupby('cca').agg(
    runs=('run', 'count'), rows_med=('rows', 'median'), dur_med_s=('duration_s', 'median'),
    interval_med_ms=('interval_med_ms', 'median'), tput_mbps_med=('tput_mbps', 'median'),
    rtt_med_ms=('rtt_med_ms', 'median'), cwnd_med=('cwnd_med', 'median'),
    data_pps_out=('data_pps_out_mean', 'median'), segs_pps_in=('segs_pps_in_mean', 'median'),
    host_total_pps=('host_total_pps_mean', 'median'), data_pps_out_max=('data_pps_out_max_interval', 'median'),
    acks_per_data=('acks_per_data_seg', 'median'), retrans_ratio=('retrans_ratio', 'median'),
    avg_seg_bytes=('avg_data_seg_bytes', 'median'), incoming_segment_fraction=('incoming_segment_fraction', 'median'),
    duration_total_s=('duration_s', 'sum'), bytes_sent_total=('bytes_sent', 'sum'),
    data_segs_out_total=('data_segs_out', 'sum'), segs_in_total=('segs_in', 'sum'))
agg['weighted_tput_mbps'] = agg.bytes_sent_total * 8 / agg.duration_total_s / 1e6
agg['weighted_data_pps_out'] = agg.data_segs_out_total / agg.duration_total_s
agg['weighted_segs_pps_in'] = agg.segs_in_total / agg.duration_total_s
agg['pooled_incoming_to_data_ratio'] = agg.segs_in_total / agg.data_segs_out_total
agg.sort_values('tput_mbps_med', ascending=False).to_csv(out / 'dctcp_per_cca_clean.csv')

quantiles = [0, .001, .01, .05, .1, .25, .5, .75, .9, .95, .99, .999, 1]
metrics = ['data_pps_out', 'segs_pps_in', 'host_total_pps', 'dt', 'rtt', 'cwnd']
qrows = []
for cca, part in [('ALL', iv), *list(iv.groupby('cca'))]:
    for metric in metrics:
        values = part[metric].quantile(quantiles)
        for q, v in values.items():
            qrows.append({'cca': cca, 'metric': metric, 'quantile': q, 'value': float(v),
                          'intervals': len(part), 'unit': 's' if metric == 'dt' else 'ms' if metric == 'rtt' else 'segments' if metric == 'cwnd' else 'segments/s'})
pd.DataFrame(qrows).to_csv(out / 'dctcp_interval_quantiles.csv', index=False)
cv = iv.groupby(['cca', 'run']).data_pps_out.agg(['std', 'mean'])
cv['cv'] = cv['std'] / cv['mean']
cv.to_csv(out / 'dctcp_per_flow_cv.csv')

def qs(series):
    return {str(q): float(v) for q, v in series.quantile(quantiles).items()}

cs = audit.loc[~audit.excluded_historical_rule]
all_counter_starts_zero = bool((cs[[c + '_first' for c in counters]] == 0).all().all())
duration_sum = float(clean.duration_s.sum())
sums = {c: int(clean[c].sum()) for c in ['bytes_sent', 'bytes_retrans', 'segs_out', 'segs_in', 'data_segs_out']}
facts = {
    'clean_flows': len(clean), 'all_flows': len(flows),
    'excluded': [f'{cca}/{run}' for cca, run in sorted(bad_keys)],
    'clean_snapshot_rows': int(clean.rows.sum()),
    'clean_candidate_intervals': int((clean.rows - 1).sum()),
    'clean_positive_dt_intervals': len(iv),
    'clean_duration_sum_s': duration_sum,
    'method': {
        'cleaning_rule': 'rows > 4000 OR last segs_out < 0 OR last segs_in < 0',
        'flow_rate': 'last cumulative counter / (last lastrcv - first lastrcv) in seconds',
        'interval_rate': 'difference of consecutive cumulative counters / positive consecutive lastrcv difference',
        'counter_starts_all_zero_clean': all_counter_starts_zero,
        'pps_unit': 'TCP socket counter segments/s; not verified as wire packets/s or CPU work/s',
        'segs_in_note': 'incoming TCP segments; pure ACK identity is unavailable from these counters',
        'quantile_method': 'linear interpolation, unweighted per interval or per flow as identified',
        'cv_std_ddof': 1,
    },
    'tput_mbps': qs(clean.tput_mbps), 'duration_s': qs(clean.duration_s),
    'rtt_med_ms': qs(clean.rtt_med_ms), 'data_pps_out_flow_mean': qs(clean.data_pps_out_mean),
    'segs_pps_in_flow_mean': qs(clean.segs_pps_in_mean), 'host_total_pps_flow_mean': qs(clean.host_total_pps_mean),
    'data_pps_out_interval': qs(iv.data_pps_out), 'segs_pps_in_interval': qs(iv.segs_pps_in),
    'host_total_pps_interval': qs(iv.host_total_pps), 'interval_dt_s': qs(iv.dt),
    'acks_per_data_seg': qs(clean.acks_per_data_seg), 'retrans_ratio': qs(clean.retrans_ratio),
    'nondata_segs_out_max': int(clean.nondata_segs_out.max()),
    'flow_cv_data_pps_med': float(cv.cv.median()),
    'sender_segs_total_med': float(clean.segs_out.median()), 'receiver_segs_total_med': float(clean.segs_in.median()),
    'zero_data_pps_intervals': int((iv.data_pps_out == 0).sum()),
    'negative_data_pps_intervals': int((iv.data_pps_out < 0).sum()),
    'negative_segs_in_pps_intervals': int((iv.segs_pps_in < 0).sum()),
    'clean_zero_dt_intervals': int(cs.zero_dt_intervals.sum()),
    'clean_negative_dt_intervals': int(cs.negative_dt_intervals.sum()),
    'counter_sums': sums,
    'weighted_rates_over_observed_duration': {
        'tput_mbps': sums['bytes_sent'] * 8 / duration_sum / 1e6,
        'data_pps_out': sums['data_segs_out'] / duration_sum,
        'segs_pps_in': sums['segs_in'] / duration_sum,
        'host_total_pps': (sums['segs_out'] + sums['segs_in']) / duration_sum,
        'incoming_to_data_ratio': sums['segs_in'] / sums['data_segs_out'],
        'incoming_segment_fraction': sums['segs_in'] / (sums['segs_out'] + sums['segs_in']),
        'retrans_bytes_ratio': sums['bytes_retrans'] / sums['bytes_sent']},
}
(out / 'dctcp_clean_facts.json').write_text(json.dumps(facts, ensure_ascii=False, indent=2) + '\n')

validation = {'all_raw_counter_start_zero_clean': all_counter_starts_zero,
              'raw_counter_missing_cells_clean': int(cs[[c + '_missing_cells' for c in counters]].sum().sum()),
              'clean_negative_counter_intervals': {c: int(cs[c + '_negative_intervals'].sum()) for c in counters}}
if a.archived_dir:
    for filename, keys in [('dctcp_per_flow.csv', ['cca', 'run']), ('dctcp_per_cca.csv', ['cca'])]:
        old = pd.read_csv(a.archived_dir / filename).set_index(keys).sort_index()
        new = pd.read_csv(out / filename).set_index(keys).sort_index()
        numeric = old.select_dtypes(include='number').columns
        same_keys = old.index.equals(new.index)
        max_difference = float((old[numeric] - new[numeric]).abs().max().max()) if same_keys else None
        tolerance_matches = bool(np.allclose(old[numeric], new[numeric], rtol=1e-12, atol=1e-9, equal_nan=True)) if same_keys else False
        validation[filename] = {'matching_keys': same_keys, 'max_absolute_numeric_difference': max_difference,
                                'allclose_rtol_1e-12_atol_1e-9': tolerance_matches}
    oldfacts = json.loads((a.archived_dir / 'dctcp_clean_facts.json').read_text())
    rounded_checks = []
    for k in ['tput_mbps', 'duration_s', 'rtt_med_ms', 'data_pps_out_interval', 'segs_pps_in_interval', 'host_total_pps_interval', 'acks_per_data_seg', 'retrans_ratio']:
        for q, oldv in oldfacts[k].items():
            newv = facts[k][q]
            decimals = len(str(oldv).split('.')[-1]) if '.' in str(oldv) else 0
            rounded_checks.append({'metric': k, 'quantile': q, 'archived': oldv, 'rebuilt': newv,
                                   'matches_archived_rounding': round(newv, decimals) == oldv})
    validation['archived_clean_fact_quantiles'] = rounded_checks
(out / 'dctcp_validation.json').write_text(json.dumps(validation, ensure_ascii=False, indent=2) + '\n')
print(json.dumps({'clean_flows': len(clean), 'clean_intervals': len(iv), 'counter_starts_all_zero_clean': all_counter_starts_zero,
                  'validation': validation, 'output': str(out)}, ensure_ascii=False, indent=2))
