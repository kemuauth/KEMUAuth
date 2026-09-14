# Published Results — Packet-Loss Sensitivity

This file records the numerical results reported in the extended version of:

> **A Drop-in KEM Replacement for Client Signatures in Post-Quantum SSH**
> IEEE ICNP 2026.

These values correspond to the packet-loss sensitivity experiment reported in
Appendix D, Table VII.

## Experiment Configuration

- Transport KEX: `mlkem768x25519-sha256`
- Server host-key authentication: Ed25519
- Compared client-authentication methods:
  - KEMUAuth with ML-KEM-768
  - ML-DSA-65
- RTT: approximately 67 ms
- TCP initial congestion window: 10 MSS
- Configured random packet-loss rates: 0%, 0.1%, 0.5%, 1.0%, and 2.0%
- End-to-end measurement: client-observed wall-clock latency of a fresh SSH invocation
- Published measurement scale: 5,000 handshakes per configuration

The default reproduction runner uses repeated batches with a reduced number of
connections for practical validation. These repetitions do not correspond to
explicitly seeded `tc/netem` random-number streams.

See `README.md` in this directory for reproduction instructions.

## Published Packet-Loss Results

| Loss (%) | Authentication Method | 50th (ms) | 95th (ms) | 99th (ms) | TCP Retransmissions per Connection |
|---:|:---|---:|---:|---:|---:|
| 0   | KEMUAuth  | 840.69 | 842.58  | 843.60  | 0.00 |
| 0   | ML-DSA-65 | 841.68 | 843.63  | 844.63  | 0.00 |
| 0.1 | KEMUAuth  | 840.51 | 842.81  | 1115.33 | 0.07 |
| 0.1 | ML-DSA-65 | 841.49 | 844.05  | 1119.90 | 0.09 |
| 0.5 | KEMUAuth  | 840.74 | 1116.64 | 1386.77 | 0.35 |
| 0.5 | ML-DSA-65 | 841.71 | 1116.99 | 1844.37 | 0.35 |
| 1.0 | KEMUAuth  | 841.00 | 1184.91 | 1865.98 | 0.75 |
| 1.0 | ML-DSA-65 | 841.93 | 1123.85 | 1876.07 | 0.78 |
| 2.0 | KEMUAuth  | 841.83 | 1774.46 | 2170.76 | 1.52 |
| 2.0 | ML-DSA-65 | 842.77 | 1676.36 | 2140.88 | 1.52 |

These are the published reference values. Files generated under `results/`
represent a new local reproduction run and may vary with hardware, operating
system state, scheduling, and network behavior.
