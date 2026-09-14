#!/usr/bin/env python3
#
# analyze.py — Ciphertext-robustness result analysis
#
# Usage:
#   python3 analyze.py protocol <raw_csv> <summary_csv> [output_md]
#   python3 analyze.py local <local_report> [output_md]

import csv
import math
import os
import sys
from collections import defaultdict
from statistics import median


MUTATION_ORDER = [
    "valid",
    "onebit",
    "multibit",
    "random",
    "allzero",
    "allff",
    "truncated",
    "extended",
]


def percentile_nearest_rank(values, percentile):
    if not values:
        return None

    ordered = sorted(values)
    rank = max(1, math.ceil(percentile * len(ordered)))
    return ordered[rank - 1]


def load_protocol_rows(raw_csv):
    with open(raw_csv, "r", newline="") as f:
        return list(csv.DictReader(f))


def analyze_protocol(raw_csv, summary_csv, output_md=None):
    rows = load_protocol_rows(raw_csv)

    groups = defaultdict(list)
    for row in rows:
        groups[row.get("mutation_type", "")].append(row)

    # ---- Machine-readable summary ----
    with open(summary_csv, "w", newline="") as f:
        writer = csv.writer(f)

        writer.writerow([
            "mutation_type",
            "total_tests",
            "response_count",
            "auth_success",
            "auth_failed",
            "other_failure",
            "connection_error",
            "timeout",
            "p50_remote_ms",
            "p95_remote_ms",
            "crash_count",
        ])

        for mutation in MUTATION_ORDER:
            items = groups.get(mutation, [])
            if not items:
                continue

            latencies = []
            response_count = 0
            success = 0
            auth_failed = 0
            other_failure = 0
            connection_error = 0
            timeout = 0
            crash_count = 0

            for item in items:
                latency = item.get("remote_latency_ms", "NA")
                if latency not in ("", "NA"):
                    try:
                        latencies.append(float(latency))
                    except ValueError:
                        pass

                if item.get("response_type", "") == "KEM_RESPONSE":
                    response_count += 1

                auth_result = item.get("auth_result", "")
                if auth_result == "success":
                    success += 1
                elif auth_result == "auth_failed":
                    auth_failed += 1
                elif auth_result == "connection_error":
                    connection_error += 1
                elif auth_result == "timeout":
                    timeout += 1
                else:
                    other_failure += 1

                error_info = item.get("error_info", "")
                if (
                    "sshd_crashed" in error_info
                    or auth_result == "sshd_died"
                ):
                    crash_count += 1

            p50 = median(latencies) if latencies else None
            p95 = percentile_nearest_rank(latencies, 0.95)

            writer.writerow([
                mutation,
                len(items),
                response_count,
                success,
                auth_failed,
                other_failure,
                connection_error,
                timeout,
                f"{p50:.3f}" if p50 is not None else "NA",
                f"{p95:.3f}" if p95 is not None else "NA",
                crash_count,
            ])

    # ---- Human-readable report ----
    lines = [
        "# Ciphertext Robustness — Protocol-Level Results",
        "",
        "| Ciphertext Class | Trials | KEM Responses | "
        "Authentication Outcome | p50 Challenge-to-Response (ms) | "
        "p95 Challenge-to-Response (ms) | Crashes |",
        "|:---|---:|---:|:---|---:|---:|---:|",
    ]

    for mutation in MUTATION_ORDER:
        items = groups.get(mutation, [])
        if not items:
            continue

        latencies = []
        response_count = 0
        success = 0
        auth_failed = 0
        other_failure = 0
        connection_error = 0
        timeout = 0
        crash_count = 0

        for item in items:
            latency = item.get("remote_latency_ms", "NA")
            if latency not in ("", "NA"):
                try:
                    latencies.append(float(latency))
                except ValueError:
                    pass

            if item.get("response_type", "") == "KEM_RESPONSE":
                response_count += 1

            auth_result = item.get("auth_result", "")
            if auth_result == "success":
                success += 1
            elif auth_result == "auth_failed":
                auth_failed += 1
            elif auth_result == "connection_error":
                connection_error += 1
            elif auth_result == "timeout":
                timeout += 1
            else:
                other_failure += 1

            error_info = item.get("error_info", "")
            if (
                "sshd_crashed" in error_info
                or auth_result == "sshd_died"
            ):
                crash_count += 1

        outcome_parts = []

        if success:
            outcome_parts.append(f"{success} success")
        if auth_failed:
            outcome_parts.append(f"{auth_failed} auth rejected")

        no_response_failures = sum(
            1
            for item in items
            if item.get("response_type", "") != "KEM_RESPONSE"
            and item.get("auth_result", "") == "other_failure"
        )

        remaining_other = other_failure - no_response_failures

        if no_response_failures:
            outcome_parts.append(
                f"{no_response_failures} rejected before response"
            )
        if remaining_other:
            outcome_parts.append(f"{remaining_other} other failure")
        if connection_error:
            outcome_parts.append(
                f"{connection_error} connection error"
            )
        if timeout:
            outcome_parts.append(f"{timeout} timeout")

        auth_outcome = (
            ", ".join(outcome_parts)
            if outcome_parts
            else "—"
        )

        p50 = median(latencies) if latencies else None
        p95 = percentile_nearest_rank(latencies, 0.95)

        lines.append(
            f"| {mutation} | {len(items)} | "
            f"{response_count}/{len(items)} | "
            f"{auth_outcome} | "
            f"{p50:.3f}" if p50 is not None else
            f"| {mutation} | {len(items)} | "
            f"{response_count}/{len(items)} | "
            f"{auth_outcome} | —"
        )

        if p50 is not None:
            # Replace the incomplete row assembled above with the full row.
            lines[-1] = (
                f"| {mutation} | {len(items)} | "
                f"{response_count}/{len(items)} | "
                f"{auth_outcome} | "
                f"{p50:.3f} | "
                f"{p95:.3f} | "
                f"{crash_count} |"
            )
        else:
            lines[-1] = (
                f"| {mutation} | {len(items)} | "
                f"{response_count}/{len(items)} | "
                f"{auth_outcome} | — | — | "
                f"{crash_count} |"
            )

    lines.extend([
        "",
        "Same-length malformed ciphertexts that reach ML-KEM "
        "decapsulation are expected to produce a KEM response but fail "
        "authentication because the derived secret differs from the "
        "server's encapsulation secret.",
        "",
        "Wrong-length ciphertexts are expected to be rejected by the "
        "client before decapsulation and therefore produce no KEM "
        "response.",
        "",
    ])

    report = "\n".join(lines)

    if output_md:
        with open(output_md, "w") as f:
            f.write(report)
    else:
        print(report)


def analyze_local(report_path, output_md=None):
    if not os.path.exists(report_path):
        print(f"[ERR] file not found: {report_path}", file=sys.stderr)
        sys.exit(1)

    with open(report_path, "r") as f:
        content = f.read()

    table = []
    in_table = False

    for line in content.splitlines():
        if line.startswith("| Ciphertext Class"):
            in_table = True

        if in_table:
            if line.startswith("|"):
                table.append(line)
            elif line.strip() == "":
                break

    if not table:
        print(
            "[ERR] no decapsulation timing table found",
            file=sys.stderr,
        )
        sys.exit(1)

    output = "\n".join([
        "# Local ML-KEM-768 Decapsulation Timing",
        "",
        *table,
        "",
        "This microbenchmark is a coarse timing sanity check only. "
        "It is not a constant-time or comprehensive side-channel "
        "evaluation.",
        "",
    ])

    if output_md:
        with open(output_md, "w") as f:
            f.write(output)
    else:
        print(output)


def main():
    if len(sys.argv) < 2:
        print("Usage:", file=sys.stderr)
        print(
            "  analyze.py protocol "
            "<raw_csv> <summary_csv> [output_md]",
            file=sys.stderr,
        )
        print(
            "  analyze.py local "
            "<local_report> [output_md]",
            file=sys.stderr,
        )
        sys.exit(1)

    mode = sys.argv[1]

    if mode == "protocol":
        if len(sys.argv) < 4:
            print(
                "[ERR] need raw_csv and summary_csv",
                file=sys.stderr,
            )
            sys.exit(1)

        analyze_protocol(
            sys.argv[2],
            sys.argv[3],
            sys.argv[4] if len(sys.argv) > 4 else None,
        )

    elif mode == "local":
        if len(sys.argv) < 3:
            print(
                "[ERR] need local report",
                file=sys.stderr,
            )
            sys.exit(1)

        analyze_local(
            sys.argv[2],
            sys.argv[3] if len(sys.argv) > 3 else None,
        )

    else:
        print(
            f"[ERR] unknown mode: {mode}",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
