#!/usr/bin/env python3
# analyze.py — Concurrent server evaluation result aggregation
#
# Read per-run data from summary.csv, compute medians across independent
# runs, and generate a human-readable Markdown report.
#
# Usage:
#   python3 analyze.py <summary_csv> [output_md]

import sys
import csv
import os
from collections import defaultdict
from statistics import median
from typing import Dict, List, Tuple

def load_summary(csv_path: str) -> List[dict]:
    """Load summary CSV, return list of rows."""
    rows = []
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows

def load_raw(raw_csv_path: str) -> dict:
    """Aggregate failure reasons from raw CSV by (concurrency, mode).
    Returns: {(concurrency, mode): {'attempted': N, 'success': N, 'failed': N, 'reasons': {reason: count}}}
    """
    from collections import defaultdict
    agg = defaultdict(lambda: {'attempted': 0, 'success': 0, 'failed': 0, 'reasons': defaultdict(int)})
    if not os.path.exists(raw_csv_path):
        return dict(agg)
    with open(raw_csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                n = int(row['concurrency'])
            except (KeyError, ValueError):
                continue
            mode = row.get('mode', '?')
            key = (n, mode)
            agg[key]['attempted'] += 1
            if row.get('success', '0') == '1':
                agg[key]['success'] += 1
            else:
                agg[key]['failed'] += 1
                reason = row.get('error_class', 'unknown')
                agg[key]['reasons'][reason] += 1
    return dict(agg)

def aggregate_by_concurrency(rows: List[dict]) -> Dict[str, Dict[str, dict]]:
    """
    Group by (concurrency, mode), compute medians for each metric.
    Returns: {concurrency: {mode: {metric: median_value}}}
    """
    groups = defaultdict(lambda: defaultdict(list))

    for row in rows:
        n = int(row['concurrency'])
        mode = row['mode']
        groups[n][mode].append(row)

    result = {}
    for n in sorted(groups.keys()):
        result[n] = {}
        for mode in ['kem', 'mldsa']:
            items = groups[n][mode]
            if not items:
                continue

            throughputs = []
            cpu_utils = []
            cpu_per_conns = []
            peak_mems = []
            p95_lats = []
            failure_rates = []
            successes = []
            failures = []
            attempteds = []

            for item in items:
                tp = item.get('throughput_conn_s', 'NA')
                cu = item.get('cpu_util_pct', 'NA')
                cpc = item.get('cpu_per_conn_ms', 'NA')
                pm = item.get('peak_memory_mb', 'NA')
                p95 = item.get('p95_latency_ms', 'NA')
                sc = item.get('success_count', '0')
                fc = item.get('failure_count', '0')
                at = item.get('attempted_count', '')
                if not at:
                    at = str(int(sc) + int(fc))

                if tp != 'NA':
                    throughputs.append(float(tp))
                if cu != 'NA':
                    cpu_utils.append(float(cu))
                if cpc != 'NA':
                    cpu_per_conns.append(float(cpc))
                if pm != 'NA':
                    peak_mems.append(float(pm))
                if p95 != 'NA':
                    p95_lats.append(float(p95))

                successes.append(int(sc))
                failures.append(int(fc))
                attempteds.append(int(at))

                # Compute failure rate
                total_att = int(at)
                if total_att > 0:
                    failure_rates.append(int(fc) / total_att * 100)

            result[n][mode] = {
                'throughput': median(throughputs) if throughputs else None,
                'cpu_util': median(cpu_utils) if cpu_utils else None,
                'cpu_per_conn': median(cpu_per_conns) if cpu_per_conns else None,
                'peak_mem': median(peak_mems) if peak_mems else None,
                'p95_latency': median(p95_lats) if p95_lats else None,
                'failure_rate': median(failure_rates) if failure_rates else 0.0,
                'total_attempted': sum(attempteds),
                'total_success': sum(successes),
                'total_failure': sum(failures),
                'runs': len(items),
            }

    return result

def fmt(val, template='.2f', na='—'):
    """Format a numeric value."""
    if val is None:
        return na
    return f'{val:{template}}'

def generate_markdown_table(agg: dict, raw_agg: dict = None) -> str:
    """Generate the aggregate Markdown results table."""
    lines = []
    lines.append('# Concurrent Server Throughput and Resource Evaluation — Results Summary')
    lines.append('')

    # ---- Main aggregate table ----
    lines.append('| Concurrent Clients N | KEM Attempted | KEM Success | KEM Failed | ML-DSA Attempted | ML-DSA Success | ML-DSA Failed | KEM conn/s | ML-DSA conn/s | Improvement% | KEM CPU% | ML-DSA CPU% | KEM CPU/conn ms | ML-DSA CPU/conn ms | KEM Mem MB | ML-DSA Mem MB | Mem Diff MB | KEM p95 ms | ML-DSA p95 ms |')
    lines.append('|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|')

    for n in sorted(agg.keys()):
        kem = agg[n].get('kem', {})
        mldsa = agg[n].get('mldsa', {})

        # Connection counts
        kem_att = str(kem.get('total_attempted', '—'))
        kem_suc = str(kem.get('total_success', '—'))
        kem_fal = str(kem.get('total_failure', '—'))
        mldsa_att = str(mldsa.get('total_attempted', '—'))
        mldsa_suc = str(mldsa.get('total_success', '—'))
        mldsa_fal = str(mldsa.get('total_failure', '—'))

        kem_tp = fmt(kem.get('throughput'))
        mldsa_tp = fmt(mldsa.get('throughput'))

        gain = '—'
        if kem.get('throughput') and mldsa.get('throughput') and mldsa['throughput'] > 0:
            g = (kem['throughput'] - mldsa['throughput']) / mldsa['throughput'] * 100
            gain = f'{g:+.1f}'

        kem_cpu = fmt(kem.get('cpu_util'))
        mldsa_cpu = fmt(mldsa.get('cpu_util'))
        kem_cpc = fmt(kem.get('cpu_per_conn'), '.3f')
        mldsa_cpc = fmt(mldsa.get('cpu_per_conn'), '.3f')
        kem_mem = fmt(kem.get('peak_mem'))
        mldsa_mem = fmt(mldsa.get('peak_mem'))

        mem_diff = '—'
        if kem.get('peak_mem') is not None and mldsa.get('peak_mem') is not None:
            diff = kem['peak_mem'] - mldsa['peak_mem']
            mem_diff = f'{diff:+.1f}'

        kem_p95 = fmt(kem.get('p95_latency'))
        mldsa_p95 = fmt(mldsa.get('p95_latency'))

        lines.append(
            f'| {n} | {kem_att} | {kem_suc} | {kem_fal} | {mldsa_att} | {mldsa_suc} | {mldsa_fal} | '
            f'{kem_tp} | {mldsa_tp} | {gain} | {kem_cpu} | {mldsa_cpu} | '
            f'{kem_cpc} | {mldsa_cpc} | {kem_mem} | {mldsa_mem} | {mem_diff} | '
            f'{kem_p95} | {mldsa_p95} |'
        )

    lines.append('')
    lines.append('## Run Statistics')
    lines.append('')
    for n in sorted(agg.keys()):
        kem = agg[n].get('kem', {})
        mldsa = agg[n].get('mldsa', {})
        kem_runs = kem.get('runs', 0)
        mldsa_runs = mldsa.get('runs', 0)
        kem_attempted = kem.get('total_attempted', 0)
        kem_success = kem.get('total_success', 0)
        kem_fail = kem.get('total_failure', 0)
        mldsa_attempted = mldsa.get('total_attempted', 0)
        mldsa_success = mldsa.get('total_success', 0)
        mldsa_fail = mldsa.get('total_failure', 0)
        lines.append(f'- N={n}: KEMUAuth {kem_attempted} attempted / {kem_success} success / {kem_fail} failed ({kem_runs} runs), ML-DSA-65 {mldsa_attempted} attempted / {mldsa_success} success / {mldsa_fail} failed ({mldsa_runs} runs)')

    return '\n'.join(lines)

def generate_failure_table(raw_agg: dict) -> str:
    """Generate failure reason detail table."""
    lines = []
    lines.append('')
    lines.append('## Failure Reason Details')
    lines.append('')

    # Collect all observed reasons
    all_reasons = set()
    for key, data in raw_agg.items():
        all_reasons.update(data['reasons'].keys())
    reason_order = sorted(all_reasons)

    # header
    header = ['Concurrency N', 'Scheme', 'Attempted', 'Success', 'Failed'] + reason_order
    lines.append('| ' + ' | '.join(header) + ' |')
    sep = [':---:' if h == 'Concurrency N' else '---:' for h in header]
    lines.append('| ' + ' | '.join(sep) + ' |')

    for n in sorted(set(k[0] for k in raw_agg.keys())):
        for mode_label, mode_key in [('KEMUAuth', 'kem'), ('ML-DSA-65', 'mldsa')]:
            key = (n, mode_key)
            data = raw_agg.get(key, {'attempted': 0, 'success': 0, 'failed': 0, 'reasons': {}})
            row = [
                str(n),
                mode_label,
                str(data['attempted']),
                str(data['success']),
                str(data['failed']),
            ]
            for reason in reason_order:
                row.append(str(data['reasons'].get(reason, 0)))
            lines.append('| ' + ' | '.join(row) + ' |')

    return '\n'.join(lines)

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <summary_csv> [output_md]", file=sys.stderr)
        sys.exit(1)

    csv_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None

    # Infer raw CSV path (raw_runs.csv in same directory)
    raw_csv_path = os.path.join(os.path.dirname(csv_path) or '.', 'raw_runs.csv')

    if not os.path.exists(csv_path):
        print(f"[ERR] summary CSV not found: {csv_path}", file=sys.stderr)
        sys.exit(1)

    rows = load_summary(csv_path)
    agg = aggregate_by_concurrency(rows)
    raw_agg = load_raw(raw_csv_path) if os.path.exists(raw_csv_path) else {}
    md = generate_markdown_table(agg, raw_agg)
    if raw_agg:
        md += '\\n' + generate_failure_table(raw_agg)

    if output_path:
        with open(output_path, 'w') as f:
            f.write(md)
        print(f"[INFO] report written to {output_path}")
    else:
        print(md)

if __name__ == '__main__':
    main()
