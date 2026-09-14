#!/usr/bin/env python3
# analyze.py — RTT sensitivity result analysis

import sys, csv, os
from collections import defaultdict
from statistics import median

def analyze(raw_csv, summary_csv, output_md=None):
    rows = []
    with open(raw_csv, 'r') as f:
        for row in csv.DictReader(f):
            rows.append(row)

    # Groups: latency data + success/failure counts + actual RTT
    groups = defaultdict(lambda: {'kem': [], 'mldsa': [], 'kem_succ': 0, 'mldsa_succ': 0,
                                   'kem_fail': 0, 'mldsa_fail': 0})
    actual_rtts = defaultdict(list)  # rtt_ms -> [measured RTT values]

    for row in rows:
        rtt = int(row['rtt_ms'])
        mode = row['mode']
        lt = row.get('latency_ms', 'NA')
        sc = row.get('success', '1')
        ar = row.get('ping_rtt_ms', '')

        if ar and ar not in ('NA', ''):
            try:
                actual_rtts[rtt].append(float(ar))
            except ValueError:
                pass

        if sc == '1':
            groups[rtt][f'{mode}_succ'] += 1
            if lt != 'NA':
                try:
                    groups[rtt][mode].append(float(lt))
                except ValueError:
                    pass
        else:
            groups[rtt][f'{mode}_fail'] += 1

    # Write summary
    with open(summary_csv, 'w') as f:
        f.write('rtt_ms,actual_rtt_ms,mode,total,successes,failures,failure_rate_pct,p50_ms,p95_ms,mean_ms\n')
        for rtt in sorted(groups.keys()):
            g = groups[rtt]
            # Actual RTT median
            act_rtts = sorted(actual_rtts.get(rtt, []))
            act_rtt = f'{act_rtts[len(act_rtts)//2]:.3f}' if act_rtts else '—'
            for mode in ['kem', 'mldsa']:
                lats = sorted(g[mode])
                if not lats:
                    continue
                n = len(lats)
                succ = g[f'{mode}_succ']
                fail = g[f'{mode}_fail']
                total = succ + fail
                fr = fail / total * 100 if total > 0 else 0.0
                p50 = lats[int(n*0.50)]
                p95 = lats[min(int(n*0.95), n-1)]
                mean_val = sum(lats) / n
                f.write(f'{rtt},{act_rtt},{mode},{total},{succ},{fail},{fr:.2f},{p50:.2f},{p95:.2f},{mean_val:.2f}\n')

    # Markdown
    lines = [
        '# RTT Sensitivity Scan',
        '',
        '| Target RTT (ms) | Actual RTT (ms) | KEMUAuth p50 (ms) | KEMUAuth p95 (ms) | ML-DSA-65 p50 (ms) | ML-DSA-65 p95 (ms) | KEMUAuth p50 Improvement (%) | Failure Rate (%) | p50 Absolute Diff (ms) |',
        '|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|',
    ]

    for rtt in sorted(groups.keys()):
        g = groups[rtt]
        kem_lats = sorted(g['kem'])
        sig_lats = sorted(g['mldsa'])

        if not kem_lats or not sig_lats:
            continue

        # Actual RTT median
        act_rtts = sorted(actual_rtts.get(rtt, []))
        act_rtt_str = f'{act_rtts[len(act_rtts)//2]:.3f}' if act_rtts else '—'

        kem_p50 = kem_lats[int(len(kem_lats)*0.50)]
        kem_p95 = kem_lats[min(int(len(kem_lats)*0.95), len(kem_lats)-1)]
        sig_p50 = sig_lats[int(len(sig_lats)*0.50)]
        sig_p95 = sig_lats[min(int(len(sig_lats)*0.95), len(sig_lats)-1)]

        gain = (sig_p50 - kem_p50) / sig_p50 * 100 if sig_p50 > 0 else 0
        abs_diff = sig_p50 - kem_p50

        # Failure rate: take the larger of the two modes (typically close under same network)
        kem_total = g['kem_succ'] + g['kem_fail']
        sig_total = g['mldsa_succ'] + g['mldsa_fail']
        kem_fr = g['kem_fail'] / kem_total * 100 if kem_total > 0 else 0
        sig_fr = g['mldsa_fail'] / sig_total * 100 if sig_total > 0 else 0
        max_fr = max(kem_fr, sig_fr)
        fr_str = f'{max_fr:.1f}' if max_fr > 0 else '0'

        lines.append(
            f'| {rtt} | {act_rtt_str} | {kem_p50:.1f} | {kem_p95:.1f} | {sig_p50:.1f} | '
            f'{sig_p95:.1f} | {gain:+.1f} | {fr_str} | {abs_diff:+.1f} |'
        )

    lines.append('')

    output = '\n'.join(lines)
    if output_md:
        with open(output_md, 'w') as f:
            f.write(output)
    else:
        print(output)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: analyze.py <raw_csv> <summary_csv> [output_md]")
        sys.exit(1)
    analyze(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
