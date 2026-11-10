#!/usr/bin/env python3
"""Summarize complete endpoint bins, sensitivity, core bounds and real samples.

Consumes phase2_endpoint_windows.py outputs; does not mix endpoints into a
server. Main high-load threshold is each endpoint/width's full-bin p90, >=20
packets. Single concentration is top1>=0.5; few-connection concentration is
top5>=0.8 and at least ten observed active tuples. Uses packet-weighted shares
as well as window quantiles. Includes low/ordinary/high load cohorts.
"""
import argparse
import csv
import gzip
import json
import math
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import numpy as np
import pandas as pd

def q(values, p):
    a = np.asarray(values)
    if not len(a): return None
    return float(np.partition(a, max(0, math.ceil(p*len(a))-1))[max(0, math.ceil(p*len(a))-1)])

def ratio(numerator, denominator):
    return float(numerator/denominator) if denominator else None

def weighted(frame, k):
    return ratio(frame[f'top{k}_packets'].sum(), frame['packets'].sum())

def local_time(ts):
    return datetime.fromtimestamp(float(ts), ZoneInfo('Asia/Shanghai')).isoformat(timespec='milliseconds')

def merge_segments(frame, endpoint, width, mode):
    result=[]; current=None
    mask=frame['is_hotspot'] if mode=='single' else frame['few_hot']
    for _,r in frame.iterrows():
        if not bool(mask.loc[r.name]):
            if current: result.append(current);current=None
            continue
        ids=[r['top1_connection']] if mode=='single' else sorted(json.loads(r['top5_connections']))
        identity=json.dumps(ids,separators=(',',':'))
        if current and (current['connection_ids']!=identity or abs(current['end_ts']-r['start_ts'])>1e-6):
            result.append(current);current=None
        if current is None:
            current={'endpoint':endpoint,'window_s':width,'kind':mode,'connection_ids':identity,
                     'start_ts':float(r['start_ts']),'end_ts':float(r['end_ts']),
                     'windows':0,'endpoint_packets':0,'dominant_packets':0,'wire_bytes':0,
                     'peak_endpoint_pps':0.,'peak_dominant_pps':0.}
        current['end_ts']=float(r['end_ts']);current['windows']+=1
        current['endpoint_packets']+=int(r['packets'])
        current['dominant_packets']+=int(r['top1_packets'] if mode=='single' else r['top5_packets'])
        current['wire_bytes']+=int(r['wire_bytes'])
        current['peak_endpoint_pps']=max(current['peak_endpoint_pps'],float(r['pps']))
        current['peak_dominant_pps']=max(current['peak_dominant_pps'],float(r['top1_packets'] if mode=='single' else r['top5_packets'])/width)
    if current:result.append(current)
    for r in result:
        r['duration_s']=r['end_ts']-r['start_ts']
        r['mean_endpoint_pps']=r['endpoint_packets']/r['duration_s']
        r['dominant_packet_share']=r['dominant_packets']/r['endpoint_packets']
        r['start_local']=local_time(r['start_ts']);r['end_local']=local_time(r['end_ts'])
    return result

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root', default=str(Path(__file__).resolve().parents[1]))
    args=ap.parse_args();root=Path(args.root);out=root/'report/phase2_mawi'
    summaries=[]
    for role,directory in [('primary','primary_windows'),('control','control_windows')]:
        summaries.append((role,json.loads((out/directory/'summary.json').read_text())))
    window_rows=[];core_rows=[];sensitivity=[];boundaries=[];cohorts=[];segments=[];profiles=[];validation=[]
    for role,summary in summaries:
        for ep,epmeta in summary['endpoints'].items():
            expected=None
            for key,meta in epmeta['windows'].items():
                path=root/meta['csv'] if not Path(meta['csv']).is_absolute() else Path(meta['csv'])
                width=float(key[:-2])/1000 if key.endswith('ms') else float(key[:-1])
                with gzip.open(path,'rt') as f:columns=next(csv.reader(f))
                if width<1:
                    use=[c for c in columns if c in {'packets','tx_packets','rx_packets','wire_bytes','tx_wire_bytes','rx_wire_bytes',
                        'payload_bytes','unknown_ports_packets','active_connections','top1_packets','top5_packets','top1_share','top5_share',
                        'partial_boundary_window','pps','wire_bits_per_s'}]
                else:use=[c for c in columns if not c.endswith('_loads')]
                frame=pd.read_csv(path,usecols=use)
                sums={c:int(frame[c].sum()) for c in ['packets','tx_packets','rx_packets','wire_bytes','tx_wire_bytes','rx_wire_bytes','payload_bytes']}
                assert sums['packets']==meta['packets']
                assert sums['tx_packets']+sums['rx_packets']==sums['packets']
                assert sums['tx_wire_bytes']+sums['rx_wire_bytes']==sums['wire_bytes']
                if expected is None:expected=sums
                else:assert sums==expected,(ep,key,sums,expected)
                valid=frame[frame['partial_boundary_window']==0].copy()
                nonempty=valid[valid['packets']>0]
                threshold=max(20,int(q(valid['packets'],.9) or 0))
                valid['high_load_threshold_packets']=threshold
                valid['is_high_load']=(valid['packets']>=threshold).astype(int)
                valid['is_hotspot']=((valid['is_high_load']==1)&(valid['top1_share']>=.5)).astype(int)
                valid['few_hot']=((valid['is_high_load']==1)&(valid['top5_share']>=.8)&(valid['active_connections']>=10)).astype(int)
                high=valid[valid['is_high_load']==1]
                row={'endpoint':ep,'role':role,'window_s':width,'complete_windows':len(valid),
                    'nonempty_complete_windows':len(nonempty),'high_load_threshold_packets':threshold,
                    'high_load_windows':len(high),'high_load_window_fraction':ratio(len(high),len(valid)),
                    'total_endpoint_packets':sums['packets'],'total_wire_bytes':sums['wire_bytes'],
                    'full_window_packets':int(valid['packets'].sum()),'excluded_boundary_packets':sums['packets']-int(valid['packets'].sum()),
                    'mean_pps_full':float(valid['packets'].mean()/width),'median_pps_full':q(valid['packets']/width,.5),
                    'p99_pps_full':q(valid['packets']/width,.99),'max_pps_full':float(valid['packets'].max()/width),
                    'median_wire_mbps_full':q(valid['wire_bytes']*8/width/1e6,.5),
                    'p99_wire_mbps_full':q(valid['wire_bytes']*8/width/1e6,.99),
                    'active_p50_nonempty':q(nonempty['active_connections'],.5),
                    'active_p50_high':q(high['active_connections'],.5),'high_pps_p50':q(high['pps'],.5),
                    'high_pps_min':float(high['pps'].min()) if len(high) else None,
                    'high_pps_max':float(high['pps'].max()) if len(high) else None,
                    'top1_p50_nonempty':q(nonempty['top1_share'],.5),'top5_p50_nonempty':q(nonempty['top5_share'],.5),
                    'top1_p50_high':q(high['top1_share'],.5),'top5_p50_high':q(high['top5_share'],.5),
                    'top1_weighted_high':weighted(high,1),'top5_weighted_high':weighted(high,5),
                    'top1_weighted_all_full':weighted(valid,1),'top5_weighted_all_full':weighted(valid,5),
                    'single_hot_windows':int(valid['is_hotspot'].sum()),'few_hot_windows':int(valid['few_hot'].sum()),
                    'single_hot_fraction_high':ratio(high['is_hotspot'].sum(),len(high)),
                    'few_hot_fraction_high':ratio(high['few_hot'].sum(),len(high)),
                    'sparse_nonempty_fraction':ratio((nonempty['packets']<20).sum(),len(nonempty)),
                    'empty_fraction_full':ratio(len(valid)-len(nonempty),len(valid))}
                window_rows.append(row)
                all_threshold=max(20,int(q(frame['packets'],.9) or 0))
                all_high=frame[frame['packets']>=all_threshold]
                boundaries.append({'endpoint':ep,'window_s':width,'all_windows':len(frame),'complete_windows':len(valid),
                    'threshold_all':all_threshold,'threshold_complete':threshold,'top1_p50_high_all':q(all_high['top1_share'],.5),
                    'top1_p50_high_complete':row['top1_p50_high'],'top5_p50_high_all':q(all_high['top5_share'],.5),
                    'top5_p50_high_complete':row['top5_p50_high']})
                for pct in [.8,.9,.95]:
                    cutoff=max(20,int(q(valid['packets'],pct) or 0));hh=valid[valid['packets']>=cutoff]
                    for share in [.4,.5,.6]:
                        sensitivity.append({'endpoint':ep,'window_s':width,'load_quantile':pct,'load_threshold_packets':cutoff,
                            'top1_share_threshold':share,'complete_windows':len(valid),'high_load_windows':len(hh),
                            'single_hot_windows':int((hh['top1_share']>=share).sum()),
                            'single_hot_fraction_high':ratio((hh['top1_share']>=share).sum(),len(hh)),
                            'top1_weighted_high':weighted(hh,1),'top5_weighted_high':weighted(hh,5)})
                p40=q(valid['packets'],.4);p60=q(valid['packets'],.6)
                definitions={'low':valid[(valid['packets']>0)&(valid['packets']<=q(valid['packets'],.25))],
                    'ordinary_p40_p60':valid[(valid['packets']>0)&(valid['packets']>=p40)&(valid['packets']<=p60)],
                    'high_p90':high}
                for name,ff in definitions.items():
                    cohorts.append({'endpoint':ep,'role':role,'window_s':width,'cohort':name,'windows':len(ff),
                        'pps_p50':q(ff['pps'],.5),'active_p50':q(ff['active_connections'],.5),
                        'top1_p50':q(ff['top1_share'],.5),'top5_p50':q(ff['top5_share'],.5),
                        'top1_weighted':weighted(ff,1),'top5_weighted':weighted(ff,5)})
                if width>=1:
                    for k in summary['parameters']['core_counts']:
                        bound=high[f'connection_bound_{k}'];lpt=high[f'lpt_{k}_imbalance'];hash0=high[f'hash_{k}_imbalance']
                        core_rows.append({'endpoint':ep,'role':role,'window_s':width,'cores':k,'high_load_windows':len(high),
                            'bound_p50':q(bound,.5),'bound_p90':q(bound,.9),'lpt_p50':q(lpt,.5),'lpt_p90':q(lpt,.9),
                            'hash0_p50':q(hash0,.5),'hash0_p90':q(hash0,.9),
                            'hash16_p50':q(high[f'hash_{k}_repeat_imbalance_p50'],.5),
                            'hash16_p90':q(high[f'hash_{k}_repeat_imbalance_p90'],.9),
                            'rr_p50':q(high[f'rr_{k}_imbalance'],.5),'rr_p90':q(high[f'rr_{k}_imbalance'],.9),
                            'connection_bound_ge1_5_fraction':ratio((bound>=1.5).sum(),len(high)),
                            'hash_avoidable_fraction':ratio(((hash0>=1.5)&(lpt<1.5)).sum(),len(high)),
                            'lpt_gap_fraction':ratio(((bound<1.5)&(lpt>=1.5)).sum(),len(high)),
                            'hash_lpt_difference_p50':q(hash0-lpt,.5)})
                        assert bool((high[f'lpt_{k}_imbalance']+1e-12>=bound).all())
                        for policy in ['hash','rr','lpt']:
                            assert bool((valid[f'{policy}_{k}_imbalance']+1e-12>=valid[f'connection_bound_{k}']).all())
                    segments.extend(merge_segments(valid,ep,width,'single'))
                    segments.extend(merge_segments(valid,ep,width,'few'))
                if width==1:
                    valid['role']=role
                    profiles.append(valid)
                validation.append({'endpoint':ep,'window_s':width,'csv_rows':len(frame),'packets':sums['packets'],
                                   'direction_and_byte_conservation':True,'complete_windows':len(valid)})
                print(f'summarized {ep} {key}: high={len(high)} single={row["single_hot_windows"]} few={row["few_hot_windows"]}',flush=True)
    for name,rows in [('window_summary',window_rows),('core_summary',core_rows),('threshold_sensitivity',sensitivity),
                      ('boundary_sensitivity',boundaries),('load_cohorts',cohorts),('hotspot_segments_complete',segments)]:
        pd.DataFrame(rows).to_csv(out/f'{name}.csv',index=False)
    endpoint_rows=[]
    for role,name in [('primary','endpoints_connections.json'),('control','controls_connections/endpoints_connections.json')]:
        conn_summary=json.loads((out/name).read_text())
        assert conn_summary['all_conservation_checks_passed']
        for ep,r in conn_summary['endpoints'].items():
            window_row=next(x for x in window_rows if x['endpoint']==ep and x['window_s']==1)
            assert r['packets']==window_row['total_endpoint_packets']
            assert r['wire_bytes']==window_row['total_wire_bytes']
            endpoint_rows.append({'endpoint':ep,'role':role,'packets':r['packets'],
                'tx_packets':r['tx_packets'],'rx_packets':r['rx_packets'],
                'wire_bytes':r['wire_bytes'],'tx_wire_bytes':r['tx_wire_bytes'],'rx_wire_bytes':r['rx_wire_bytes'],
                'observed_connections':r['observed_connections'],
                'both_direction_connections':r['both_directions']['connections'],
                'both_direction_packet_fraction':r['both_directions']['packets_fraction'],
                'both_direction_wire_byte_fraction':r['both_directions']['wire_bytes_fraction'],
                'connection_packets_p50':r['connection_quantiles']['packets']['p50'],
                'connection_packets_p99':r['connection_quantiles']['packets']['p99'],
                'connection_wire_bytes_p50':r['connection_quantiles']['wire_bytes']['p50'],
                'connection_duration_s_p50':r['connection_quantiles']['observed_duration_s']['p50'],
                'connection_duration_s_p99':r['connection_quantiles']['observed_duration_s']['p99'],
                'all_trace_top1_packet_share':r['top1_total_packet_share'],
                'all_trace_top5_packet_share':r['top5_total_packet_share']})
    pd.DataFrame(endpoint_rows).to_csv(out/'endpoint_statistics.csv',index=False)
    profile=pd.concat(profiles,ignore_index=True)
    profile.to_csv(out/'window_profiles_1s.csv.gz',index=False,compression='gzip')
    single=[s for s in segments if s['kind']=='single' and s['window_s']==1]
    samples=[]
    if single:
        best=max(single,key=lambda r:(r['duration_s'],r['endpoint_packets']))
        samples.append({'name':'hotspot','endpoint':best['endpoint'],'start_ts':best['start_ts'],'end_ts':best['end_ts'],
                        'reason':'longest same-connection high-load concentration segment in full 1s bins'})
    balanced=profile[(profile['is_high_load']==1)&(profile['active_connections']>=10)&(profile['top1_share']<=.2)&(profile['top5_share']<=.5)]
    balanced_rule='high load, active>=10, top1<=0.2, top5<=0.5'
    if balanced.empty:
        balanced=profile[(profile['active_connections']>=10)&(profile['packets']>=20)]
        balanced_rule='relative least-concentrated observed full bin; strict balanced condition unavailable'
    if len(balanced):
        br=balanced.sort_values(['top5_share','top1_share','packets'],ascending=[True,True,False]).iloc[0]
        samples.append({'name':'balanced','endpoint':br['endpoint'],'start_ts':float(br['start_ts']),'end_ts':float(br['end_ts']),
                        'reason':balanced_rule})
    ordinary=[]
    for ep,ff in profile.groupby('endpoint'):
        p40=q(ff['packets'],.4);p60=q(ff['packets'],.6)
        cc=ff[(ff['packets']>=p40)&(ff['packets']<=p60)&(ff['packets']>=20)&(ff['active_connections']>=10)]
        if len(cc):
            target=q(ff['top1_share'],.5)
            cc=cc.copy();cc['_distance']=abs(cc['top1_share']-target)
            ordinary.append(cc.sort_values('_distance').iloc[0])
    if ordinary:
        rr=min(ordinary,key=lambda r:r['top1_share'])
        samples.append({'name':'ordinary','endpoint':rr['endpoint'],'start_ts':float(rr['start_ts']),'end_ts':float(rr['end_ts']),
                        'reason':'endpoint p40..p60 packet load; share nearest own median; active>=10'})
    sample_dir=out/'samples';sample_dir.mkdir(exist_ok=True)
    for item in samples:
        ff=profile[(profile['endpoint']==item['endpoint'])&(profile['start_ts']>=item['start_ts'])&(profile['end_ts']<=item['end_ts'])]
        item.update(start_local=local_time(item['start_ts']),end_local=local_time(item['end_ts']),
                    role=str(ff['role'].iloc[0]),
                    endpoint_packets=int(ff['packets'].sum()),wire_bytes=int(ff['wire_bytes'].sum()),
                    mean_pps=float(ff['packets'].sum()/(item['end_ts']-item['start_ts'])),
                    top1_weighted=weighted(ff,1),top5_weighted=weighted(ff,5),active_p50=q(ff['active_connections'],.5),
                    path=f'report/phase2_mawi/samples/{item["name"]}.tsv.gz')
    handles={s['name']:gzip.open(root/s['path'],'wt',compresslevel=2) for s in samples}
    observed_counts={s['name']:0 for s in samples}
    for path in [root/'data/mawi/mawi_endpoints.tsv',root/'data/mawi/phase2_controls.tsv']:
        source_role='primary' if path.name=='mawi_endpoints.tsv' else 'control'
        source_samples=[s for s in samples if s['role']==source_role]
        with path.open() as stream:
            for line in stream:
                fields=line.split('\t',4);t=float(fields[0]);src,dst=fields[2:4]
                for s in source_samples:
                    if s['start_ts']<=t<s['end_ts'] and s['endpoint'] in [src,dst]:
                        handles[s['name']].write(line);observed_counts[s['name']]+=1
    for h in handles.values():h.close()
    for s in samples:
        assert observed_counts[s['name']]==s['endpoint_packets'],(s,observed_counts)
        s['extracted_packets']=observed_counts[s['name']]
    pd.DataFrame(samples).to_csv(out/'representative_samples.csv',index=False)
    (out/'representative_samples.json').write_text(json.dumps(samples,ensure_ascii=False,indent=2)+'\n')
    (out/'validation.json').write_text(json.dumps({'all_checks_passed':True,'window_checks':validation,
        'sample_counts':observed_counts,'complete_bin_threshold':'p90 of all full bins, at least 20 packets',
        'single_hotspot':'high load and top1>=0.5, same observed tuple in consecutive full bins',
        'few_hotspot':'high load and top5>=0.8 and active>=10, same top5 set in consecutive full bins',
        'core_disentangling':'single-connection bound vs feasible LPT; packing/LPT gaps retained separately',
        'later_phase_tcp_events_run':False},ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'samples':samples,'windows':len(window_rows),'core_rows':len(core_rows)},ensure_ascii=False,indent=2))

if __name__=='__main__':main()
