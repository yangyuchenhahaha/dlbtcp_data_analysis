#!/usr/bin/env python3
"""Index recovered inputs and record SHA256 without running later analyses."""
import argparse
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
REQUIRED = [
    'data/mawi/202512311400.pcap.gz', 'data/mawi/202512311400.pcap',
    'data/mawi/mawi_all.tsv', 'data/mawi/mawi_tcp_sorted.tsv.gz',
    'data/mawi/mawi_endpoints.tsv', 'data/uni2/univ2_trace.tgz',
    *[f'data/uni2/univ2_pt{i}' for i in range(9)],
    'data/uni2/tcp_only/univ2_tcp_all.pcap', 'data/uni2/tcp_only/univ2_tcp_all.tsv',
    'data/dctcp/tcp-dataset.zip',
    'data/facebook/facebook_cluster_a_10min.json', 'data/facebook/facebook_cluster_b_10min.json',
    'data/awsazure/ds.tar.gz', 'report/dctcp/dctcp_intervals.csv.gz',
    'report/rebuilt_20261005/dctcp/dctcp_intervals_clean.csv.gz',
    'report/rebuilt_20261005/mawi_prepared_inputs.json',
    'report/rebuilt_20261005/phase1_mawi_bidir.json',
    'report/rebuilt_20261005/mawi_capture_inventory.json',
    'report/auxiliary_data_validation_20261005.json',
    'report/rebuilt_20261005/parser_validation.json',
    'report/rebuilt_20261005/mawi_sorted_input_validation.json',
]

def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(8 << 20), b''):
            h.update(chunk)
    return h.hexdigest()

def entry(path):
    return {'path': str(path.relative_to(BASE)), 'bytes': path.stat().st_size,
            'sha256': digest(path)}

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--workers', type=int, default=4)
    args = ap.parse_args()
    missing = [p for p in REQUIRED if not (BASE/p).is_file() or (BASE/p).stat().st_size == 0]
    if missing:
        raise SystemExit('Required inputs missing: ' + ', '.join(missing))
    files = sorted(p for p in (BASE/'data').rglob('*') if p.is_file()
                   and not p.name.endswith('.part')
                   and not any(c.startswith('.') for c in p.relative_to(BASE/'data').parts))
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        records = list(pool.map(entry, files))
    prepared = json.loads((BASE/'report/rebuilt_20261005/mawi_prepared_inputs.json').read_text())
    capture = json.loads((BASE/'report/rebuilt_20261005/mawi_capture_inventory.json').read_text())
    dctcp = json.loads((BASE/'report/rebuilt_20261005/dctcp/dctcp_validation.json').read_text())
    aux = json.loads((BASE/'report/auxiliary_data_validation_20261005.json').read_text())
    by_path = {r['path']: r for r in records}
    assert by_path['data/mawi/202512311400.pcap.gz']['bytes'] == 3591643125
    assert len(list((BASE/'data/dctcp').rglob('*.csv'))) == 850
    assert prepared['source_tcp_rows'] == 55783111
    assert capture['packets'] == 146511670
    sources = {
        'mawi': {'url': 'https://mawi.wide.ad.jp/mawi/samplepoint-F/2025/202512311400.pcap.gz',
                 'http_content_length': 3591643125, 'gzip_crc': 'passed during complete gzip decompression',
                 'pcap_record_scan': 'complete with successful libpcap EOF',
                 'official_hash_available': False},
        'uni2': json.loads((BASE/'data/uni2/source_provenance.json').read_text()),
        'dctcp': {'url': 'https://zenodo.org/records/10894768', 'bytes': 75442290,
                  'zenodo_md5': '4ea56b47b3a454177ce2a5e971b19ff5', 'md5_and_zip_crc': 'passed'},
        'facebook': json.loads((BASE/'data/facebook/source_manifest.json').read_text()),
        'awsazure': json.loads((BASE/'data/awsazure/source_manifest.json').read_text()),
    }
    md5 = hashlib.md5((BASE/'data/dctcp/tcp-dataset.zip').read_bytes()).hexdigest()
    assert md5 == sources['dctcp']['zenodo_md5']
    assert by_path['data/uni2/univ2_trace.tgz']['sha256'] == sources['uni2']['sha256']
    assert by_path['data/awsazure/ds.tar.gz']['sha256'] == sources['awsazure']['sha256']
    for fb in sources['facebook']:
        assert by_path[fb['path']]['sha256'] == fb['sha256']
    groups = {}
    for name in ['mawi','uni2','dctcp','facebook','awsazure']:
        members = [r for r in records if r['path'].startswith('data/'+name+'/')]
        groups[name] = {'files': len(members), 'bytes': sum(r['bytes'] for r in members)}
    context = []
    for p in [BASE.parent/'DLBTCP_对话记录_20261005.md', BASE.parent/'main(4).pdf']:
        if p.is_file(): context.append({'path': str(p), 'bytes': p.stat().st_size, 'sha256': digest(p)})
    manifest = {
        'date': '2026-10-05', 'timezone': 'Asia/Shanghai',
        'status': 'inputs_recovered_and_validated', 'required_inputs_present': True,
        'project_basis': context,
        'phase2_requirements': {'main_sample': 'MAWI TCP subset', 'windows_s': [1,10,60],
                                'packet_sampling_accepted': True, 'load_unit': 'packets'},
        'phase2_and_phase3_real_trace_analysis_run': False,
        'required_paths': REQUIRED, 'sources': sources, 'groups': groups,
        'data_files': records, 'data_file_count': len(records),
        'total_data_bytes': sum(r['bytes'] for r in records),
        'prepared_mawi_inputs': prepared,
        'validation_reports': ['report/rebuilt_20261005/parser_validation.json',
            'report/rebuilt_20261005/mawi_sorted_input_validation.json',
            'report/rebuilt_20261005/dctcp/dctcp_validation.json',
            'report/auxiliary_data_validation_20261005.json'],
        'preserved_validation_results': {'dctcp': dctcp, 'auxiliary': aux},
        'candidate_datasets_not_obtained': [
            {'name': 'CAIDA', 'status': 'not obtained; requires separate authorized access'},
            {'name': 'UNI1', 'status': 'not obtained; original conversation records an email application route'},
            {'name': 'Facebook original packet CSV', 'status': 'not obtained; available GitHub matrices cannot reconstruct it'},
        ],
        'uni2_endpoint_summary_rerun': 'not run; escalation request was rejected by user; raw inputs and capture inventories are present',
    }
    destination = BASE/'report/data_manifest_20261005.json'
    destination.write_text(json.dumps(manifest, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps({'manifest': str(destination), 'data_files': len(records),
                      'total_data_bytes': manifest['total_data_bytes'], 'groups': groups}, ensure_ascii=False, indent=2))

if __name__ == '__main__': main()
