#!/usr/bin/env python3
#
# analyze.py — Pending-authentication-state memory analysis
#
# Fit KEMUAuth and ML-DSA-65 independently using the actually observed
# simultaneous pending/paused connection count from every experimental run.
# The two fitted models are then evaluated at common pending counts P.
#
# Usage:
#   python3 analyze.py <summary_csv> [output_md]
#
# Optional:
#   --normalized-p=16,32,64,128,172
#   --explicit-state-bytes=2384

import argparse
import csv
import os
from collections import defaultdict
from typing import Dict, List, Optional, Tuple


PAPER_NORMALIZED_P = [16, 32, 64, 128, 172]

# Paper-aligned accounting value for the explicitly retained KEMUAuth
# challenge context. This is protocol-specific state, not total SSH
# per-connection memory.
PAPER_EXPLICIT_STATE_BYTES = 2384


def parse_int(value: str) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_float(value: str) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def load_summary(csv_path: str) -> List[dict]:
    rows = []
    with open(csv_path, "r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def collect_fit_points(rows: List[dict]) -> Dict[str, List[Tuple[int, float]]]:
    """
    Collect per-run fit points:

        (observed pending/paused count, peak memory MiB)

    The fit deliberately uses pending_estimate rather than target_concurrency.
    P=0 is excluded because the paper compares the growth of concurrently
    pending authentication states and the baseline is not run at P=0.
    """
    points = defaultdict(list)

    for row in rows:
        mode = row.get("mode", "")
        if mode not in ("kem", "baseline"):
            continue

        observed_p = parse_int(row.get("pending_estimate", ""))
        peak_mem = parse_float(row.get("peak_memory_mb", ""))

        if observed_p is None or peak_mem is None:
            continue
        if observed_p <= 0:
            continue

        points[mode].append((observed_p, peak_mem))

    return dict(points)


def linear_fit(points: List[Tuple[int, float]]) -> Optional[Tuple[float, float, float]]:
    """
    Ordinary least-squares fit:

        M(P) = alpha + beta * P

    Returns (alpha, beta, R^2).
    """
    if len(points) < 2:
        return None

    xs = [float(p) for p, _ in points]
    ys = [float(m) for _, m in points]

    n = len(xs)
    sx = sum(xs)
    sy = sum(ys)
    sxx = sum(x * x for x in xs)
    sxy = sum(x * y for x, y in zip(xs, ys))

    denom = n * sxx - sx * sx
    if denom == 0:
        return None

    beta = (n * sxy - sx * sy) / denom
    alpha = (sy - beta * sx) / n

    mean_y = sy / n
    ss_tot = sum((y - mean_y) ** 2 for y in ys)
    ss_res = sum(
        (y - (alpha + beta * x)) ** 2
        for x, y in zip(xs, ys)
    )

    if ss_tot == 0:
        r2 = 1.0
    else:
        r2 = 1.0 - ss_res / ss_tot

    return alpha, beta, r2


def parse_normalized_points(spec: str) -> List[int]:
    values = []

    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue

        try:
            value = int(item)
        except ValueError as exc:
            raise ValueError(
                f"invalid normalized pending count: {item}"
            ) from exc

        if value <= 0:
            raise ValueError(
                f"normalized pending count must be positive: {value}"
            )

        values.append(value)

    if not values:
        raise ValueError("normalized pending-count list is empty")

    return values


def cleanup_summary(rows: List[dict]) -> Tuple[int, int]:
    """
    Count KEMUAuth measurement runs whose pending state was cleaned up.

    New summary files contain final_pending explicitly. For older result files,
    cleanup_ok is used as a compatibility fallback.
    """
    total = 0
    cleaned = 0

    for row in rows:
        if row.get("mode") != "kem":
            continue

        target = parse_int(row.get("target_concurrency", ""))
        if target is None or target <= 0:
            continue

        total += 1

        final_pending = parse_int(row.get("final_pending", ""))
        if final_pending is not None:
            if final_pending == 0:
                cleaned += 1
            continue

        cleanup_ok = row.get("cleanup_ok", "").strip().upper()
        if cleanup_ok == "YES":
            cleaned += 1

    return cleaned, total


def generate_report(
    rows: List[dict],
    normalized_ps: List[int],
    explicit_state_bytes: int,
) -> str:

    points = collect_fit_points(rows)

    kem_points = points.get("kem", [])
    baseline_points = points.get("baseline", [])

    kem_fit = linear_fit(kem_points)
    baseline_fit = linear_fit(baseline_points)

    if kem_fit is None:
        raise ValueError(
            "insufficient valid KEMUAuth fit points; "
            "need at least two positive observed pending counts"
        )

    if baseline_fit is None:
        raise ValueError(
            "insufficient valid ML-DSA-65 baseline fit points; "
            "need at least two positive observed paused counts"
        )

    kem_alpha, kem_beta, kem_r2 = kem_fit
    base_alpha, base_beta, base_r2 = baseline_fit

    lines = []

    lines.append(
        "# Pending Authentication State Memory — Results Summary"
    )
    lines.append("")

    lines.append("## Analysis Method")
    lines.append("")
    lines.append(
        "KEMUAuth and ML-DSA-65 are fitted independently using the "
        "actually observed simultaneous pending/paused connection count "
        "from each run, rather than the requested target concurrency."
    )
    lines.append("")
    lines.append(
        "For each method, peak server memory is modeled as:"
    )
    lines.append("")
    lines.append("```text")
    lines.append("M(P) = alpha + beta * P")
    lines.append("```")
    lines.append("")
    lines.append(
        "The two fitted models are then evaluated at the same normalized "
        "pending count P."
    )
    lines.append("")

    lines.append("## Fit Inputs")
    lines.append("")
    lines.append(
        "| Authentication Method | Fit Points | "
        "Observed P Range |"
    )
    lines.append("|:---|---:|:---:|")

    kem_min = min(p for p, _ in kem_points)
    kem_max = max(p for p, _ in kem_points)
    base_min = min(p for p, _ in baseline_points)
    base_max = max(p for p, _ in baseline_points)

    lines.append(
        f"| KEMUAuth | {len(kem_points)} | {kem_min}–{kem_max} |"
    )
    lines.append(
        f"| ML-DSA-65 | {len(baseline_points)} | "
        f"{base_min}–{base_max} |"
    )
    lines.append("")

    lines.append("## Independent Linear Fits")
    lines.append("")
    lines.append("```text")
    lines.append(
        f"M_KEMUAuth(P) = {kem_alpha:.4f} "
        f"+ {kem_beta:.5f} * P   MiB"
    )
    lines.append(
        f"M_ML-DSA(P)   = {base_alpha:.4f} "
        f"+ {base_beta:.5f} * P   MiB"
    )
    lines.append("```")
    lines.append("")
    lines.append(
        f"- KEMUAuth: beta = {kem_beta:.5f} MiB/connection, "
        f"R^2 = {kem_r2:.5f}"
    )
    lines.append(
        f"- ML-DSA-65: beta = {base_beta:.5f} MiB/connection, "
        f"R^2 = {base_r2:.5f}"
    )
    lines.append("")

    lines.append("## Normalized Memory Comparison")
    lines.append("")
    lines.append(
        "| Normalized Pending P | "
        "Estimated KEMUAuth Peak Memory (MiB) | "
        "Estimated ML-DSA-65 Peak Memory (MiB) | "
        "Memory Difference (MiB) | "
        "Explicit KEM State (MiB) |"
    )
    lines.append("|---:|---:|---:|---:|---:|")

    for p in normalized_ps:
        kem_mem = kem_alpha + kem_beta * p
        base_mem = base_alpha + base_beta * p
        diff = kem_mem - base_mem

        explicit_mib = (
            explicit_state_bytes * p / (1024.0 * 1024.0)
        )

        lines.append(
            f"| {p} | "
            f"{kem_mem:.2f} | "
            f"{base_mem:.2f} | "
            f"{diff:.2f} | "
            f"{explicit_mib:.3f} |"
        )

    lines.append("")

    common_min = max(kem_min, base_min)
    common_max = min(kem_max, base_max)

    extrapolated = [
        p for p in normalized_ps
        if p < common_min or p > common_max
    ]

    if extrapolated:
        joined = ", ".join(str(p) for p in extrapolated)
        lines.append(
            f"> Note: normalized P value(s) {joined} fall outside the "
            f"common observed range {common_min}–{common_max}. "
            "Those rows are extrapolations of the fitted models."
        )
        lines.append("")

    lines.append("## Explicit KEMUAuth Challenge State")
    lines.append("")
    lines.append(
        f"The paper-aligned implementation accounting uses "
        f"**{explicit_state_bytes:,} bytes per pending KEMUAuth "
        "challenge**."
    )
    lines.append("")
    lines.append("```text")
    lines.append(
        f"M_explicit(P) = {explicit_state_bytes} * P / 2^20 MiB"
    )
    lines.append("```")
    lines.append("")
    lines.append(
        "This value represents explicitly retained KEMUAuth-specific "
        "challenge state. It is not the total memory consumption of an "
        "SSH connection."
    )
    lines.append("")

    cleaned, total = cleanup_summary(rows)

    lines.append("## Cleanup Check")
    lines.append("")
    if total > 0:
        lines.append(
            f"- KEMUAuth measurement runs cleaned up successfully: "
            f"{cleaned}/{total}"
        )
    else:
        lines.append(
            "- No positive-P KEMUAuth measurement runs were available "
            "for cleanup analysis."
        )
    lines.append("")

    lines.append("## Interpretation")
    lines.append("")
    lines.append(
        "The fitted per-connection slopes primarily reflect ordinary "
        "OpenSSH process, socket, transport, and other per-connection "
        "state. They must not be interpreted as KEMUAuth challenge-state "
        "memory."
    )
    lines.append("")
    lines.append(
        "The KEMUAuth-specific challenge-state contribution is reported "
        "separately using the explicit per-pending-challenge accounting "
        "above."
    )
    lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Analyze pending-authentication-state memory measurements "
            "using independent fits over observed pending counts."
        )
    )

    parser.add_argument(
        "summary_csv",
        help="pending-memory summary.csv",
    )

    parser.add_argument(
        "output_md",
        nargs="?",
        help="optional Markdown report output path",
    )

    parser.add_argument(
        "--normalized-p",
        default=",".join(str(p) for p in PAPER_NORMALIZED_P),
        help=(
            "comma-separated normalized pending counts "
            "(default: 16,32,64,128,172)"
        ),
    )

    parser.add_argument(
        "--explicit-state-bytes",
        type=int,
        default=PAPER_EXPLICIT_STATE_BYTES,
        help=(
            "explicit KEMUAuth state per pending challenge in bytes "
            "(default: 2384)"
        ),
    )

    args = parser.parse_args()

    if not os.path.exists(args.summary_csv):
        parser.error(
            f"summary CSV not found: {args.summary_csv}"
        )

    if args.explicit_state_bytes <= 0:
        parser.error(
            "--explicit-state-bytes must be positive"
        )

    try:
        normalized_ps = parse_normalized_points(args.normalized_p)
    except ValueError as exc:
        parser.error(str(exc))

    rows = load_summary(args.summary_csv)

    try:
        report = generate_report(
            rows,
            normalized_ps,
            args.explicit_state_bytes,
        )
    except ValueError as exc:
        print(f"[ERR] {exc}")
        raise SystemExit(1)

    if args.output_md:
        with open(args.output_md, "w") as f:
            f.write(report)
        print(f"[INFO] report written to {args.output_md}")
    else:
        print(report)


if __name__ == "__main__":
    main()
