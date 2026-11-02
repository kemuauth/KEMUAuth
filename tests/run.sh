#!/usr/bin/env bash
# Run maintained draft-00 verification and/or SSH integration tests.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

usage() {
    printf 'Usage: bash tests/run.sh [--vectors|--integration]\n'
}

mode="${1:-all}"
if (( $# > 1 )); then
    usage >&2
    exit 2
fi
case "$mode" in
    all|--vectors|--integration) ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac

if [[ "$mode" == all || "$mode" == --vectors ]]; then
    printf '\n== KEMUAuth ML-KEM-768 draft vector verification ==\n'
    make -f Makefile -f tests/protocol/Makefile.kem-blob \
        kem-real-vector-check
fi
if [[ "$mode" == all || "$mode" == --integration ]]; then
    printf '\n== KEMUAuth local SSH integration checks ==\n'
    bash tests/integration/run.sh
fi
printf '\nPASS: requested KEMUAuth test suites completed.\n'
