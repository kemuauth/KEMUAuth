# Published Results — RTT Sensitivity

This file records the numerical results reported in the extended version of:

> **A Drop-in KEM Replacement for Client Signatures in Post-Quantum SSH**
> IEEE ICNP 2026.

These values correspond to the RTT-sensitivity experiment reported in
Appendix D, Table VI.

## Experiment Configuration

- Transport KEX: `mlkem768x25519-sha256`
- Server host-key authentication: Ed25519
- Compared client-authentication methods:
  - KEMUAuth with ML-KEM-768
  - ML-DSA-65
- TCP initial congestion window: 10 MSS
- Configured RTT range: 0–200 ms
- End-to-end measurement: client-observed wall-clock latency of a fresh SSH invocation
- Published measurement scale: 5,000 handshakes per configuration

The default reproduction runner uses a reduced measurement count for practical
validation. See `README.md` in this directory for reproduction instructions.

## Published RTT-Sensitivity Results

| RTT (ms) | KEMUAuth 50th (ms) | KEMUAuth 95th (ms) | ML-DSA-65 50th (ms) | ML-DSA-65 95th (ms) | Δ50 (ms) |
|---:|---:|---:|---:|---:|---:|
| 0   | 74.23   | 76.59   | 77.57   | 79.15   | 3.34 |
| 20  | 329.97  | 331.81  | 331.51  | 333.88  | 1.54 |
| 40  | 550.86  | 553.20  | 552.14  | 555.19  | 1.28 |
| 60  | 770.96  | 772.55  | 772.16  | 773.85  | 1.20 |
| 80  | 990.83  | 993.33  | 992.01  | 994.50  | 1.18 |
| 100 | 1211.03 | 1212.57 | 1211.67 | 1214.08 | 0.64 |
| 120 | 1431.31 | 1433.31 | 1432.28 | 1434.27 | 0.97 |
| 160 | 1870.96 | 1872.57 | 1872.24 | 1874.26 | 1.28 |
| 200 | 2310.94 | 2313.86 | 2312.00 | 2314.49 | 1.06 |

`Δ50` denotes the difference between the ML-DSA-65 and KEMUAuth median
handshake latencies.

These are the published reference values. Files generated under `results/`
represent a new local reproduction run and may vary with hardware, operating
system state, scheduling, and network configuration.
