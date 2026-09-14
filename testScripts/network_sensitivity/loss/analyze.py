#!/usr/bin/env python3
# analyze.py — Packet-loss sensitivity result analysis
#
# Usage:
#   python3 analyze.py <raw_csv> <summary_csv> <retrans_csv> [output_md]

import sys, csv, os
from collections import defaultdict

def load_retrans(retrans_csv):
    """Load batch-level TCP retransmission stats, aggregate by (loss_pct, mode)."""
    batches = defaultdict(lambda: defaultdict(list))
    try:
        with open(retrans_csv, 'r') as f:
            for row in csv.DictReader(f):
                loss = row['loss_pct']
                mode = row.get('mode', 'all')
                delta = row.get('tcp_retrans_delta', 'NA')
                total = row.get('total_conns', '0')
                if delta != 'NA' and delta.lstrip('-').isdigit():
                    batches[loss][mode].append((int(delta), int(total)))
    except (FileNotFoundError, KeyError):
        pass
    return batches

def compute_avg_retrans(batches, loss, mode):
    """Compute average TCP retransmissions per attempted connection."""
    items = batches.get(loss, {}).get(mode, [])
    if not items:
        return "NA"
    total_retrans = sum(d for d, _ in items)
    total_conns = sum(t for _, t in items)
    if total_conns == 0:
        return "NA"
    return f"{total_retrans / total_conns:.2f}"

def analyze(raw_csv, summary_csv, retrans_csv=None, output_md=None):
    rows = []
    with open(raw_csv, 'r') as f:
        for row in csv.DictReader(f):
            rows.append(row)

    # Load TCP retransmission stats
    batches = load_retrans(retrans_csv) if retrans_csv else {}

    groups = defaultdict(lambda: defaultdict(list))
    for row in rows:
        loss = row['loss_pct']
        mode = row['mode']
        lt = row.get('latency_ms', 'NA')
        sc = row.get('success', '0')
        try:
            lat = float(lt) if lt != 'NA' else None
        except ValueError:
            lat = None
        groups[loss][mode].append((lat, sc == '1'))

    with open(summary_csv, 'w') as f:
        f.write('loss_pct,mode,total,successes,failures,failure_rate_pct,p50_ms,p95_ms,p99_ms,mean_ms,avg_tcp_retrans_per_conn\n')
        for loss in sorted(groups.keys(), key=float):
            for mode in ['kem', 'mldsa']:
                items = groups[loss].get(mode, [])
                if not items:
                    continue
                total = len(items)
                succ = sum(1 for it in items if it[1])
                fail = total - succ
                fr = fail / total * 100 if total > 0 else 0
                lats = sorted(
                    it[0] for it in items
                    if it[1] and it[0] is not None
                )
                n = len(lats)
                if n == 0:
                    continue
                p50 = lats[int(n*0.50)]
                p95 = lats[min(int(n*0.95), n-1)]
                p99 = lats[min(int(n*0.99), n-1)]
                mean_val = sum(lats) / n
                avg_retrans = compute_avg_retrans(batches, loss, mode)
                f.write(f'{loss},{mode},{total},{succ},{fail},{fr:.2f},{p50:.2f},{p95:.2f},{p99:.2f},{mean_val:.2f},{avg_retrans}\n')

    lines = [
        '# Random Packet-Loss Sensitivity',
        '',
        '| Loss Rate (%) | Scheme | Successful Connections | Failure Rate (%) | p50 (ms) | p95 (ms) | p99 (ms) | Avg TCP Retrans/Connection |',
        '|:---:|:---|:---:|:---:|:---:|:---:|:---:|:---:|',
    ]

    for loss in sorted(groups.keys(), key=float):
        for mode in ['kem', 'mldsa']:
            items = groups[loss].get(mode, [])
            if not items:
                continue
            total = len(items)
            succ = sum(1 for it in items if it[1])
            fail = total - succ
            fr = fail / total * 100 if total > 0 else 0
            lats = sorted(
                it[0] for it in items
                if it[1] and it[0] is not None
            )
            n = len(lats)
            if n == 0:
                continue
            p50 = lats[int(n*0.50)]
            p95 = lats[min(int(n*0.95), n-1)]
            p99 = lats[min(int(n*0.99), n-1)]
            avg_retrans = compute_avg_retrans(batches, loss, mode)
            label = 'KEMUAuth' if mode == 'kem' else 'ML-DSA-65'
            lines.append(f'| {loss} | {label} | {succ} | {fr:.2f} | {p50:.1f} | {p95:.1f} | {p99:.1f} | {avg_retrans} |')

    lines.append('')

    output = '\n'.join(lines)
    if output_md:
        with open(output_md, 'w') as f:
            f.write(output)
    else:
        print(output)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: analyze.py <raw_csv> <summary_csv> [retrans_csv] [output_md]")
        sys.exit(1)
    analyze(sys.argv[1], sys.argv[2],
           sys.argv[3] if len(sys.argv) > 3 and os.path.exists(sys.argv[3]) else None,
           sys.argv[4] if len(sys.argv) > 4 else None)
