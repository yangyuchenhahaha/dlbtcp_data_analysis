#!/usr/bin/env python3
"""Record phase-2 sources, scripts, outputs and successful validation checks."""
import hashlib
import json
import platform
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'report/phase2_mawi'

def record(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        while block:=f.read(16*1024*1024):h.update(block)
    return {'path':str(path.relative_to(ROOT)),'bytes':path.stat().st_size,'sha256':h.hexdigest()}

def main():
    validation=json.loads((OUT/'validation.json').read_text())
    audit=json.loads((OUT/'independent_audit.json').read_text())
    assert validation['all_checks_passed']
    assert audit['all_checks_passed']
    selection=json.loads((ROOT/'report/phase2_mawi_control_selection.json').read_text())
    recovered=json.loads((ROOT/'report/data_manifest_20261005.json').read_text())
    previous={r['path']:r for r in recovered['data_files']}
    sources=[record(ROOT/p) for p in ['data/mawi/mawi_endpoints.tsv','data/mawi/phase2_controls.tsv']]
    assert sources[0]['sha256']==previous[sources[0]['path']]['sha256']
    assert sources[1]['sha256']==selection['output_sha256']
    full=previous['data/mawi/mawi_tcp_sorted.tsv.gz']
    assert full['sha256']==selection['input_sha256']
    scripts=['extract_phase2_controls.py','phase2_connection_totals.py','phase2_endpoint_windows.py',
             'test_phase2_endpoint_windows.py','summarize_phase2_mawi.py','plot_phase2_mawi.py',
             'plot_phase2_samples.py','run_phase2_mawi.sh','build_phase2_manifest.py']
    artifacts=[record(p) for p in sorted(OUT.rglob('*')) if p.is_file() and p.name!='analysis_manifest.json']
    assert len(validation['window_checks'])==36
    result={'date':'2026-10-05','status':'phase2_complete','phase2_real_trace_analysis_run':True,
      'phase3_real_trace_analysis_run':False,'python':platform.python_version(),
      'common_span_unix':[1767157200.398184,1767158100.170696],
      'window_seconds':[.001,.01,.1,1,10,60],'principal_window_seconds':1,
      'core_counts':[2,4,8,16,32],'core_window_seconds':[1,10,60],'hash_seeds':16,
      'core_load_basis':'observed endpoint TCP packet count; no measured CPU cost',
      'full_tcp_source':full,'inputs':sources,
      'provenance_records':[record(ROOT/'report/phase2_mawi_control_selection.json'),
                            record(ROOT/'report/data_manifest_20261005.json')],
      'scripts':[record(ROOT/'scripts'/s) for s in scripts],
      'artifacts':artifacts,'artifact_count':len(artifacts),
      'validation_passed':True,'independent_audit_passed':True,
      'definitions':'report/phase2_mawi/phase2_report_20261005.md',
      'reproduce':'bash scripts/run_phase2_mawi.sh',
      'limits':['Six purposively selected endpoints over approximately 15 minutes.',
                'Backbone-link visibility is not the endpoint complete server load.',
                'Observed four-tuples are not split into reused TCP sessions.',
                'TCP byte rates use original pcap lengths; concentration and cores use packet counts.',
                'Per-window top-k packet-weighted shares may change connection identities.']}
    (OUT/'analysis_manifest.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'status':result['status'],'artifact_count':len(artifacts),'validated_inputs':sources},indent=2))

if __name__=='__main__':main()
