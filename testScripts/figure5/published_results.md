# Figure 5 / Table X — Published Results

This file records the numerical client-observed end-to-end SSH latency results
published for **Figure 5** of the ICNP 2026 paper and **Table X** of the
extended arXiv version.

These values are the canonical published results and are provided for
comparison with independently reproduced runs.

## Experimental Configuration

- Transport key exchange: `mlkem768x25519-sha256`
- RTT: approximately 67 ms
- TCP MSS: 1460 bytes
- TCP initial congestion windows:
  `3, 5, 7, 10, 15, 20, 25, 30, 35, 40, 50` MSS
- Measurement: client-observed wall-clock latency of a fresh SSH invocation
- Published measurement count: 5,000 handshakes per configuration
- Reported statistics: P5, P50, and P95 latency

All latency values below are in milliseconds.

## Case A — Ed25519 + Ed25519

Client authentication: Ed25519
Server authentication: Ed25519

| initcwnd (MSS) | P5 | P50 | P95 |
| ---: | ---: | ---: | ---: |
| 3 | 861.92 | 863.91 | 870.43 |
| 5 | 862.84 | 867.87 | 871.95 |
| 7 | 862.07 | 867.14 | 871.34 |
| 10 | 859.23 | 864.15 | 868.61 |
| 15 | 862.22 | 866.97 | 871.07 |
| 20 | 860.24 | 864.87 | 868.92 |
| 25 | 859.52 | 864.93 | 869.72 |
| 30 | 861.46 | 864.13 | 870.20 |
| 35 | 859.94 | 863.49 | 869.28 |
| 40 | 859.60 | 861.44 | 867.76 |
| 50 | 861.10 | 864.77 | 870.32 |

## Case B — ML-DSA-65 + ML-DSA-65

Client authentication: ML-DSA-65
Server authentication: ML-DSA-65

| initcwnd (MSS) | P5 | P50 | P95 |
| ---: | ---: | ---: | ---: |
| 3 | 995.07 | 997.38 | 1002.71 |
| 5 | 924.08 | 925.85 | 931.75 |
| 7 | 855.44 | 858.63 | 864.56 |
| 10 | 860.18 | 864.78 | 867.94 |
| 15 | 858.09 | 862.08 | 865.26 |
| 20 | 856.57 | 861.04 | 864.85 |
| 25 | 857.50 | 862.15 | 866.56 |
| 30 | 858.35 | 860.82 | 866.06 |
| 35 | 859.60 | 862.38 | 867.48 |
| 40 | 857.23 | 859.22 | 864.47 |
| 50 | 860.71 | 862.17 | 867.35 |

## Case C — SLH-DSA-SHA2-192f + SLH-DSA-SHA2-192f

Client authentication: SLH-DSA-SHA2-192f
Server authentication: SLH-DSA-SHA2-192f

| initcwnd (MSS) | P5 | P50 | P95 |
| ---: | ---: | ---: | ---: |
| 3 | 1236.59 | 1238.92 | 1246.12 |
| 5 | 1167.80 | 1172.74 | 1178.35 |
| 7 | 1169.28 | 1173.71 | 1179.30 |
| 10 | 1036.09 | 1042.69 | 1047.26 |
| 15 | 1038.97 | 1044.33 | 1048.63 |
| 20 | 1036.98 | 1043.01 | 1047.72 |
| 25 | 968.77 | 975.13 | 980.04 |
| 30 | 904.29 | 907.19 | 912.07 |
| 35 | 904.52 | 908.02 | 912.84 |
| 40 | 901.47 | 904.88 | 910.10 |
| 50 | 904.15 | 906.76 | 911.24 |

## Case D — ML-KEM-768 + ML-DSA-65

Client authentication: ML-KEM-768
Server authentication: ML-DSA-65

| initcwnd (MSS) | P5 | P50 | P95 |
| ---: | ---: | ---: | ---: |
| 3 | 925.17 | 927.34 | 932.20 |
| 5 | 856.51 | 858.14 | 863.13 |
| 7 | 856.67 | 861.01 | 865.06 |
| 10 | 859.44 | 863.44 | 867.21 |
| 15 | 856.95 | 859.97 | 863.45 |
| 20 | 857.35 | 861.69 | 865.77 |
| 25 | 859.12 | 864.28 | 867.88 |
| 30 | 859.54 | 862.40 | 866.26 |
| 35 | 858.80 | 861.37 | 866.01 |
| 40 | 856.06 | 858.28 | 863.77 |
| 50 | 858.97 | 862.48 | 866.57 |

## Case E — ML-KEM-768 + SLH-DSA-SHA2-192f

Client authentication: ML-KEM-768
Server authentication: SLH-DSA-SHA2-192f

| initcwnd (MSS) | P5 | P50 | P95 |
| ---: | ---: | ---: | ---: |
| 3 | 1014.53 | 1016.93 | 1021.97 |
| 5 | 1012.55 | 1014.71 | 1021.00 |
| 7 | 1012.38 | 1017.61 | 1021.15 |
| 10 | 945.45 | 950.18 | 955.06 |
| 15 | 946.43 | 951.21 | 955.22 |
| 20 | 944.99 | 950.44 | 954.85 |
| 25 | 948.44 | 953.63 | 958.28 |
| 30 | 879.94 | 883.03 | 887.58 |
| 35 | 881.66 | 884.58 | 888.73 |
| 40 | 879.60 | 882.63 | 888.24 |
| 50 | 879.59 | 883.04 | 887.17 |

## Reproduction Note

A local execution of:

```bash
bash testScripts/figure5/run
```

writes independently reproduced measurements under:

```text
testScripts/figure5/results/test3/
```

The paper-aligned quantile output is generated in:

```text
window_p5_p50_p95.csv
```

and the human-readable summary is written to:

```text
readable.md
```

Locally reproduced values may differ from the published measurements because
of hardware, operating-system state, CPU behavior, scheduling, and background
load.

The values in this file should therefore be treated as the reference values
reported in the published paper, while files under `results/` should be treated
as outputs of a particular reproduction run.
