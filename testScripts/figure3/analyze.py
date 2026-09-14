#!/usr/bin/env python3
# analyze.py — Figure 3 client-authentication algorithm comparison
# Input: raw_runs.csv (alg,round,phase,iter,latency_ms,success,retcode,auth_mode)
# Only phase=="measure" samples with success==1 are used for statistics.
# Output: summary.csv + readable.md

import csv
import sys
from collections import defaultdict

ALG_ORDER = [
    "ed25519", "md44", "md65", "md87", "falcon512", "falcon1024",
    "sd128f", "sd192f", "sd256f", "mk512", "mk768", "mk1024", "password",
]

ALG_NAMES = {
    "ed25519": ("Ed25519", "ed25519"),
    "md44": ("ML-DSA-44", "md44"),
    "md65": ("ML-DSA-65", "md65"),
    "md87": ("ML-DSA-87", "md87"),
    "falcon512": ("Falcon-512", "falcon512"),
    "falcon1024": ("Falcon-1024", "falcon1024"),
    "sd128f": ("SLH-DSA-SHA2-128f", "sd128f"),
    "sd192f": ("SLH-DSA-SHA2-192f", "sd192f"),
    "sd256f": ("SLH-DSA-SHA2-256f", "sd256f"),
    "mk512": ("ML-KEM-512", "mk512"),
    "mk768": ("ML-KEM-768", "mk768"),
    "mk1024": ("ML-KEM-1024", "mk1024"),
    "password": ("Password (yescrypt)", "password"),
}

def pct(sorted_vals, q):
    """nearest-rank percentile"""
    if not sorted_vals:
        return float("nan")
    n = len(sorted_vals)
    idx = int(q * n + 0.999999)
    if idx < 1:
        idx = 1
    if idx > n:
        idx = n
    return sorted_vals[idx - 1]

def main():
    if len(sys.argv) < 8:
        print("usage: analyze.py raw.csv summary.csv readable.md rtt initcwnd iterations warmup")
        sys.exit(1)
    raw_path, summary_path, readable_path = sys.argv[1:4]
    rtt_ms, initcwnd, iterations, warmup = sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7]

    # alg -> list of success latencies (measure only)
    samples = defaultdict(list)
    total_measure = defaultdict(int)
    failures = defaultdict(int)

    with open(raw_path) as f:
        for r in csv.DictReader(f):
            alg = r["alg"]
            phase = r["phase"]
            if phase != "measure":
                continue
            total_measure[alg] += 1
            if r["success"] != "1":
                failures[alg] += 1
                continue
            try:
                lat = float(r["latency_ms"])
            except (ValueError, TypeError):
                failures[alg] += 1
                continue
            samples[alg].append(lat)

    # summary.csv
    with open(summary_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["alg", "auth_mode", "total_measure", "successes", "failures",
                    "failure_rate_pct", "mean_ms", "p50_ms", "p95_ms"])
        rows = []
        for alg in ALG_ORDER:
            if alg not in total_measure:
                continue
            vals = sorted(samples.get(alg, []))
            n = len(vals)
            mean = sum(vals) / n if n else float("nan")
            p50 = pct(vals, 0.50)
            p95 = pct(vals, 0.95)
            fail = failures.get(alg, 0)
            total = total_measure.get(alg, 0)
            fail_rate = (fail / total * 100.0) if total else float("nan")
            rows.append((alg, mean, p50, p95, n, fail, total, fail_rate))
            w.writerow([alg, "", total, n, fail, f"{fail_rate:.2f}",
                        f"{mean:.3f}", f"{p50:.3f}", f"{p95:.3f}"])

    # readable.md
    lines = []
    lines.append("# Figure 3 - Client-Authentication Algorithm Comparison")
    lines.append("")
    lines.append(f"Run config: RTT={rtt_ms}ms, initcwnd={initcwnd} MSS, "
                 f"iterations={iterations}, warmup={warmup}")
    lines.append("")
    lines.append("| Client authentication algorithm | Notation | Mean (ms) | Median / P50 (ms) | P95 (ms) | Success |")
    lines.append("|:---|:---|:---:|:---:|:---:|:---:|")
    for alg, mean, p50, p95, n, fail, total, fail_rate in rows:
        name, notn = ALG_NAMES.get(alg, (alg, alg))
        ok = "OK" if fail == 0 else f"{n}/{total}"
        lines.append(f"| {name} | `{notn}` | {mean:.3f} | {p50:.3f} | {p95:.3f} | {ok} |")
    lines.append("")
    lines.append("> Latency is client-observed wall-clock time around a fresh SSH invocation. Only successful measure-phase samples are included.")
    with open(readable_path, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"[OK] summary: {summary_path}")
    print(f"[OK] readable: {readable_path}")

if __name__ == "__main__":
    main()
