#!/usr/bin/env python3
"""Create reproducible MAWI phase-2 figures from the common postprocessor CSVs.

Only complete windows are plotted.  The input summaries must use the same
definition: high load = packets >= endpoint/window p90 AND packets >= 20,
including threshold ties.  Shares and core work refer to observed packets.

Run from the project directory:
  PYTHONPATH="$PWD/.python-packages" MPLCONFIGDIR="$PWD/.mplconfig" \
    python3 scripts/plot_phase2_mawi.py

English figure text avoids machine-specific CJK font dependencies; the JSON
figure manifest maps the A--F endpoint labels to full IP strings and roles.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault('MPLCONFIGDIR', str(ROOT / '.mplconfig'))
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.ticker import MaxNLocator, PercentFormatter, ScalarFormatter
import numpy as np
import pandas as pd

ENDPOINTS = [
    '150.74.240.107', '203.42.121.173', '203.42.117.47',
    '2001:fab8:1071:93ea:700:1a:3fc1:7e80', '202.249.10.115', '43.15.244.195',
]
COLORS = ['#0072B2', '#D55E00', '#009E73', '#CC79A7', '#E69F00', '#56B4E9']
LETTERS = dict(zip(ENDPOINTS, 'ABCDEF'))
CAPTURE_START = 1767157200.398184
COMMON_NOTE = 'Observed link traffic from six selected endpoints; the figures do not estimate all server traffic.'


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        while chunk := f.read(8 * 1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def endpoint_title(ip):
    role = 'primary' if ENDPOINTS.index(ip) < 3 else 'control candidate'
    return f'{LETTERS[ip]}  {ip}  ({role})'


def short_title(ip):
    return f'{LETTERS[ip]}  IPv6' if ':' in ip else f'{LETTERS[ip]}  {ip}'


def window_label(width):
    return f'{width * 1000:g} ms' if width < 1 else f'{width:g} s'


def require_columns(frame, columns, name):
    missing = set(columns) - set(frame.columns)
    if missing:
        raise ValueError(f'{name}: missing columns {sorted(missing)}')


def boolean(series):
    if pd.api.types.is_bool_dtype(series) or pd.api.types.is_numeric_dtype(series):
        return series.astype(bool).to_numpy()
    return series.str.lower().isin(['1', 'true', 'yes']).to_numpy()


def save(fig, out_dir, name, outputs, caption):
    for suffix in ['png', 'pdf']:
        path = out_dir / f'{name}.{suffix}'
        fig.savefig(path, dpi=180, bbox_inches='tight',
                    metadata={'Creator': 'scripts/plot_phase2_mawi.py'})
        outputs.append(dict(path=str(path.resolve()), bytes=path.stat().st_size,
                            sha256=digest(path), caption=caption))
    plt.close(fig)


def timeline(profiles, out_dir, outputs, capture_start):
    fig, axes = plt.subplots(6, 1, figsize=(13.5, 16), sharex=True)
    for ax, ip in zip(axes, ENDPOINTS):
        data = profiles[profiles.endpoint == ip].sort_values('start_ts')
        if data.empty:
            raise ValueError(f'No complete 1s profile rows for {ip}')
        x = (data.start_ts.to_numpy(dtype=float) + .5 - capture_start) / 60
        pps = data.pps.to_numpy(dtype=float)
        high = boolean(data.is_high_load)
        hot = high & (data.top1_share.to_numpy(dtype=float) >= .5)
        share_ax = ax.twinx()
        nonempty = data.packets.to_numpy() > 0
        top1 = np.where(nonempty, data.top1_share.to_numpy(dtype=float), np.nan)
        top5 = np.where(nonempty, data.top5_share.to_numpy(dtype=float), np.nan)
        ax.step(x, pps, where='mid', color='#444444', linewidth=.8)
        share_ax.step(x, top1, where='mid', color='#0072B2', linewidth=.7, alpha=.85)
        share_ax.step(x, top5, where='mid', color='#009E73', linewidth=.7, alpha=.65)
        ax.scatter(x[high], pps[high], s=12, facecolors='none', edgecolors='#E69F00',
                   linewidths=.65, zorder=4)
        ax.scatter(x[hot], pps[hot], s=12, color='#D55E00', linewidths=0, zorder=5)
        ax.set_title(endpoint_title(ip), loc='left', fontsize=9.5)
        ax.set_ylabel('Packets/s')
        share_ax.set_ylabel('Connection share')
        share_ax.set_ylim(0, 1.05)
        share_ax.yaxis.set_major_formatter(PercentFormatter(1))
        share_ax.set_yticks([0, .5, 1])
        ax.set_ylim(bottom=0)
        ax.grid(axis='y', alpha=.18)
        ax.yaxis.set_major_locator(MaxNLocator(4))
        formatter = ScalarFormatter(useOffset=False)
        formatter.set_scientific(False)
        ax.yaxis.set_major_formatter(formatter)
        ax.text(.99, .93, f'{int(high.sum())} high-load bins; {int(hot.sum())} with top1 >= 50%',
                transform=ax.transAxes, fontsize=8, ha='right', va='top',
                bbox=dict(facecolor='white', edgecolor='none', alpha=.7))
    axes[-1].set_xlabel('Minutes since capture start (1767157200.398184 Unix seconds)')
    axes[-1].set_xlim(0, 15)
    fig.suptitle('Endpoint packet rate and connection concentration: complete 1-second windows',
                 fontsize=14, y=.99)
    handles = [Line2D([], [], color='#444444', label='Endpoint packets/s'),
               Line2D([], [], color='#0072B2', label='Top 1 packet share'),
               Line2D([], [], color='#009E73', label='Top 5 packet share'),
               Line2D([], [], marker='o', markerfacecolor='none', color='#E69F00',
                      linestyle='none', label='High load (p90 and >=20 packets)'),
               Line2D([], [], marker='o', color='#D55E00', linestyle='none',
                      label='High load + top 1 >=50%')]
    fig.legend(handles=handles, loc='lower center', ncol=3, bbox_to_anchor=(.5, .036), fontsize=9)
    fig.text(.5, .012, COMMON_NOTE, ha='center', fontsize=8)
    fig.tight_layout(rect=(0, .08, 1, .974), h_pad=1.05)
    save(fig, out_dir, '01_endpoint_timelines_1s', outputs,
         'Six endpoint timelines: packet rate, top1/top5 packet shares, high-load bins and concentrated high-load bins; complete 1s windows only.')


def matrix(summary, widths, field):
    return np.array([[float(summary.loc[(summary.endpoint == ip) &
                                        np.isclose(summary.window_s, width), field].iloc[0])
                      for width in widths] for ip in ENDPOINTS])


def heatmap(ax, values, widths, title, *, cmap='viridis', vmin=0, vmax=1,
            percentage=True, numeric_format='.0f'):
    masked = np.ma.masked_invalid(values)
    handle = ax.imshow(masked, aspect='auto', interpolation='nearest', cmap=cmap, vmin=vmin, vmax=vmax)
    ax.set_xticks(range(len(widths)), [window_label(w) for w in widths])
    ax.set_yticks(range(6), [short_title(ip) for ip in ENDPOINTS])
    ax.tick_params(labelsize=8)
    ax.set_title(title, fontsize=10, pad=9)
    for y in range(values.shape[0]):
        for x in range(values.shape[1]):
            value = values[y, x]
            if np.isfinite(value):
                rgba = handle.cmap(handle.norm(value))
                luminance = .2126 * rgba[0] + .7152 * rgba[1] + .0722 * rgba[2]
                color = 'white' if luminance < .48 else 'black'
                text = f'{value * 100:.0f}%' if percentage else format(value, numeric_format)
                ax.text(x, y, text, ha='center', va='center', color=color, fontsize=8)
            else:
                ax.text(x, y, 'n/a', ha='center', va='center', fontsize=8)
    return handle


def window_comparison(summary, out_dir, outputs):
    widths = sorted(summary.window_s.unique())
    fig, axes = plt.subplots(2, 3, figsize=(17, 8.5))
    fields = [('top1_p50_nonempty', 'Median top 1 share: all nonempty complete bins'),
              ('top5_p50_nonempty', 'Median top 5 share: all nonempty complete bins'),
              ('top1_p50_high', 'Median top 1 share: high-load complete bins'),
              ('top5_p50_high', 'Median top 5 share: high-load complete bins')]
    for (row, col), (field, title) in zip([(0, 0), (0, 1), (1, 0), (1, 1)], fields):
        heatmap(axes[row, col], matrix(summary, widths, field), widths, title, cmap='YlGnBu')
    # Packet occupancy provides a direct check against misleading shares in sparse bins.
    packets = matrix(summary, widths, 'median_pps_full') * np.array(widths)[None, :]
    log_values = np.log10(np.maximum(packets, 1))
    ax = axes[0, 2]
    handle = ax.imshow(log_values, aspect='auto', interpolation='nearest', cmap='cividis',
                       vmin=0, vmax=max(1, float(np.nanmax(log_values))))
    ax.set_xticks(range(len(widths)), [window_label(w) for w in widths])
    ax.set_yticks(range(6), [short_title(ip) for ip in ENDPOINTS])
    ax.set_title('Median packets/bin: all complete bins\nColor scale is log10(max(packets, 1))', fontsize=10)
    ax.tick_params(labelsize=8)
    for y in range(6):
        for x in range(len(widths)):
            v = packets[y, x]
            label = f'{v:,.0f}' if v < 100_000 else f'{v / 1000:.0f}k'
            color = 'white' if handle.norm(log_values[y, x]) < .53 else 'black'
            ax.text(x, y, label, ha='center', va='center', color=color, fontsize=8)
    heatmap(axes[1, 2], matrix(summary, widths, 'sparse_nonempty_fraction'), widths,
            'Sparse fraction of nonempty complete bins\nFewer than 20 packets/bin', cmap='magma')
    fig.suptitle('Window-size sensitivity: concentration and packet sparsity', fontsize=14, y=.98)
    fig.text(.5, .012, 'High load: endpoint/window p90 and >=20 packets, including ties. '
             'All cells use complete windows. A-C primary; D-F control candidates.',
             ha='center', fontsize=8)
    fig.tight_layout(rect=(0, .045, 1, .955), h_pad=2, w_pad=2)
    save(fig, out_dir, '02_window_concentration_and_sparsity', outputs,
         'Top1/top5 medians among all nonempty versus high-load complete bins, median packet occupancy across all complete bins, and sparse nonempty-bin fractions.')


def core_comparison(cores, out_dir, outputs, hash16_method):
    selected = cores[np.isclose(cores.window_s, 1)].copy()
    counts = [2, 4, 8, 16, 32]
    fig, axes = plt.subplots(3, 2, figsize=(13.5, 12), sharex=True)
    specs = [('bound_p50', 'Indivisible-connection lower bound', '#333333', '--', 'o'),
             ('lpt_p50', 'LPT heuristic', '#009E73', '-', 's'),
             ('rr_p50', 'Fixed round robin', '#0072B2', '-', '^'),
             ('hash0_p50', 'Hash simulation, seed 0', '#999999', ':', 'x'),
             ('hash16_p50', 'Hash simulations, 16 seeds', '#D55E00', '-', 'D')]
    for ax, ip in zip(axes.flat, ENDPOINTS):
        data = selected[selected.endpoint == ip].set_index('cores').reindex(counts)
        if data.index.isna().any() or data['bound_p50'].isna().any():
            raise ValueError(f'Missing 1s core summaries for {ip}')
        x = np.arange(len(counts))
        for field, name, color, style, marker in specs:
            ax.plot(x, data[field].to_numpy(), color=color, linestyle=style,
                    marker=marker, markersize=4, linewidth=1.1, label=name,
                    zorder=4 if field == 'bound_p50' else 2)
        ax.axhline(1, color='#666666', linewidth=.6, alpha=.6)
        ax.set_title(short_title(ip), loc='left', fontsize=10)
        ax.set_xticks(x, [str(k) for k in counts])
        ax.set_ylabel('Max-core / ideal mean load')
        ax.set_ylim(bottom=.8)
        ax.yaxis.set_major_locator(MaxNLocator(5))
        ax.grid(axis='y', alpha=.2)
        ax.text(.03, .94, f'{int(data.high_load_windows.iloc[0])} high-load 1s bins',
                transform=ax.transAxes, fontsize=8, va='top')
    for ax in axes[-1]:
        ax.set_xlabel('Number of simulated cores')
    fig.suptitle('Packet-work imbalance in high-load 1-second windows: median ratios', fontsize=14, y=.99)
    handles, labels = axes.flat[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc='lower center', ncol=3, bbox_to_anchor=(.5, .043), fontsize=9)
    note = 'Bound = max(1, cores x top1 packet share). LPT is a greedy per-window heuristic; hash is simulated, not measured RSS.'
    fig.text(.5, .024, note, ha='center', fontsize=8)
    fig.text(.5, .008, hash16_method, ha='center', fontsize=8)
    fig.tight_layout(rect=(0, .105, 1, .972), h_pad=1.2)
    save(fig, out_dir, '03_highload_core_imbalance', outputs,
         'High-load complete 1s median core imbalance ratios for K=2,4,8,16,32. Lower bound, per-window LPT heuristic, fixed RR, deterministic seed-0 hash and 16-seed hash summaries. ' + hash16_method)


def concentration_cdf(profiles, out_dir, outputs):
    fig, axes = plt.subplots(1, 2, figsize=(13.5, 5.5), sharey=True)
    for ax, field, title in zip(axes, ['top1_share', 'top5_share'],
                               ['Largest connection', 'Five largest connections']):
        for ip, color in zip(ENDPOINTS, COLORS):
            data = profiles[profiles.endpoint == ip]
            high = boolean(data.is_high_load)
            values = data.loc[high, field].to_numpy(dtype=float)
            values = values[np.isfinite(values)]
            if len(values) == 0:
                raise ValueError(f'No high-load 1s concentration values for {ip}')
            unique, counts = np.unique(values, return_counts=True)
            xx = np.r_[0, unique, 1]
            yy = np.r_[0, counts.cumsum() / len(values), 1]
            role = 'primary' if ENDPOINTS.index(ip) < 3 else 'control'
            ax.step(xx, yy, where='post', color=color, linewidth=1.4,
                    linestyle='-' if role == 'primary' else '--',
                    label=f'{short_title(ip)} ({role}, n={len(values)})')
        ax.set_title(title, fontsize=11)
        ax.set_xlabel('Packet share in one complete 1s window')
        # Keep the large jump at a share of exactly 100% visibly inside the axes.
        ax.set_xlim(-.005, 1.02)
        ax.set_ylim(-.005, 1.02)
        ax.set_xticks(np.linspace(0, 1, 6))
        ax.xaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.grid(alpha=.18)
        if field == 'top1_share':
            ax.axvline(.5, color='#555555', linewidth=.8, linestyle=':', alpha=.7)
    axes[0].set_ylabel('Fraction of high-load windows (empirical CDF)')
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc='lower center', ncol=3, bbox_to_anchor=(.5, .045), fontsize=8)
    fig.suptitle('Connection concentration among high-load 1-second windows', fontsize=14, y=.99)
    fig.text(.5, .008, 'High load: endpoint p90 and >=20 packets, including ties. '
             'Each endpoint contributes its own windows; these are purposive examples.',
             ha='center', fontsize=8)
    fig.tight_layout(rect=(0, .19, 1, .94))
    save(fig, out_dir, '04_highload_concentration_cdf', outputs,
         'Endpoint-specific empirical CDFs of top1/top5 packet shares in complete high-load 1s bins. Primary endpoints use solid lines; control candidates use dashed lines.')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--report-dir', type=Path, default=ROOT / 'report/phase2_mawi')
    parser.add_argument('--out-dir', type=Path)
    parser.add_argument('--capture-start', type=float, default=CAPTURE_START)
    parser.add_argument('--hash16-method', default='Hash 16 seeds: median across seeds within each window, then median across high-load windows.')
    args = parser.parse_args()
    out_dir = args.out_dir or args.report_dir / 'figures'
    paths = [args.report_dir / name for name in
             ['window_summary.csv', 'core_summary.csv', 'window_profiles_1s.csv.gz']]
    for path in paths:
        if not path.is_file():
            parser.error(f'Required completed input is missing: {path}')
    summary, cores, profiles = [pd.read_csv(path) for path in paths]
    require_columns(summary, ['endpoint', 'role', 'window_s', 'top1_p50_nonempty',
                             'top5_p50_nonempty', 'top1_p50_high', 'top5_p50_high',
                             'median_pps_full', 'sparse_nonempty_fraction'], 'window_summary.csv')
    require_columns(cores, ['endpoint', 'window_s', 'cores', 'high_load_windows',
                           'bound_p50', 'lpt_p50', 'rr_p50', 'hash0_p50', 'hash16_p50'], 'core_summary.csv')
    require_columns(profiles, ['endpoint', 'role', 'window_s', 'start_ts', 'packets',
                              'pps', 'top1_share', 'top5_share', 'is_high_load',
                              'partial_boundary_window'], 'window_profiles_1s.csv.gz')
    if set(ENDPOINTS) - set(summary.endpoint):
        raise ValueError('The common summary does not contain all six selected endpoints')
    if summary.duplicated(['endpoint', 'window_s']).any():
        raise ValueError('Duplicate endpoint/window summary rows')
    if cores.duplicated(['endpoint', 'window_s', 'cores']).any():
        raise ValueError('Duplicate endpoint/window/core summary rows')
    if (profiles.partial_boundary_window != 0).any() or not np.isclose(profiles.window_s, 1).all():
        raise ValueError('Profiles must contain complete 1s windows only')
    out_dir.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 9,
                         'axes.spines.top': False, 'axes.spines.right': False,
                         'pdf.fonttype': 42, 'savefig.facecolor': 'white'})
    outputs = []
    timeline(profiles, out_dir, outputs, args.capture_start)
    window_comparison(summary, out_dir, outputs)
    core_comparison(cores, out_dir, outputs, args.hash16_method)
    concentration_cdf(profiles, out_dir, outputs)
    manifest = dict(script=str(Path(__file__).resolve()),
                    inputs=[dict(path=str(p.resolve()), bytes=p.stat().st_size, sha256=digest(p)) for p in paths],
                    outputs=outputs, capture_start=args.capture_start,
                    endpoint_labels=[dict(label=LETTERS[ip], endpoint=ip,
                                          role='primary' if i < 3 else 'control',
                                          color=COLORS[i]) for i, ip in enumerate(ENDPOINTS)],
                    methodology=dict(complete_windows_only=True,
                                     high_load='packets >= endpoint/window complete-bin p90 AND packets >=20; ties included',
                                     unit='observed packet counts; CPU costs are not measured',
                                     core_bound='max(1, K * top1 packet share)',
                                     lpt='Greedy whole-connection reassignment in each window; not an optimal allocation',
                                     hash='Seeded deterministic hash simulation, not actual RSS',
                                     hash16_summary=args.hash16_method,
                                     concentration_empty_bins='empty bins are omitted from concentration medians/CDFs',
                                     sample='Six purposively selected endpoints; control status is assessed per window'))
    manifest_path = out_dir / 'figure_manifest.json'
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(dict(output_files=len(outputs), manifest=str(manifest_path)), indent=2))


if __name__ == '__main__':
    main()
