# KEMUAuth Evaluation and Reproducibility Scripts

This directory contains the evaluation and reproducibility scripts for
**KEMUAuth**, including the experiments reported in the ICNP 2026 paper and
the extended arXiv version.

The scripts are organized by their role in the final paper rather than by the
internal numbering used during development.

## Directory Overview

```text
testScripts/
├── figure3/
│   └── Client-authentication algorithm comparison
├── figure4/
│   └── Migration configurations across RTT regimes
├── figure5/
│   └── TCP initial-window sensitivity
├── concurrency/
│   ├── throughput_cgroup/
│   └── pending_memory/
├── network_sensitivity/
│   ├── rtt_scan/
│   └── loss/
├── implementation_checks/
│   └── ciphertext_robustness/
├── backends/
│   └── Shared experiment infrastructure
├── README.md
└── run_main_figures
```

The `figure3/`, `figure4/`, and `figure5/` directories correspond directly to
Figures 3–5 of the paper. Extended evaluations and implementation-level checks
are grouped separately.

## Main Paper Experiments

### Figure 3 — Client-Authentication Algorithm Comparison

Directory:

```text
testScripts/figure3/
```

Entry point:

```bash
sudo bash testScripts/figure3/run
```

Figure 3 compares 13 client-authentication configurations while keeping the SSH
transport key exchange, server authentication, RTT, and TCP initial congestion
window fixed.

The directory contains:

- `README.md` — experiment description and reproduction instructions
- `run` — experiment runner
- `analyze.py` — result-processing script
- `published_results.md` — numerical results published in Figure 3 / Table VIII
- `results/` — output from a new local reproduction run

See `testScripts/figure3/README.md` for the complete configuration.

### Figure 4 — Migration Configurations across RTT Regimes

Directory:

```text
testScripts/figure4/
```

Entry point:

```bash
bash testScripts/figure4/run
```

Figure 4 evaluates eight practical client/server authentication migration
configurations under approximately 37 ms, 67 ms, and 163 ms RTTs.

The paper-aligned runner explicitly selects the combined
classical/post-quantum authentication paths required by the hybrid profiles.

The directory contains:

- `README.md` — experiment description and reproduction instructions
- `run` — experiment runner
- `published_results.md` — numerical results published in Figure 4 / Table IX
- `results/` — output from a new local reproduction run

See `testScripts/figure4/README.md` for the complete configuration.

### Figure 5 — TCP Initial-Window Sensitivity

Directory:

```text
testScripts/figure5/
```

Entry point:

```bash
bash testScripts/figure5/run
```

Figure 5 evaluates five client/server authentication configurations while
varying the TCP initial congestion window across:

```text
3 5 7 10 15 20 25 30 35 40 50 MSS
```

The RTT is fixed at approximately 67 ms.

The directory contains:

- `README.md` — experiment description and reproduction instructions
- `run` — experiment runner
- `published_results.md` — numerical results published in Figure 5 / Table X
- `results/` — output from a new local reproduction run

See `testScripts/figure5/README.md` for the complete configuration.

## Running the Three Main Figures

The top-level entry point:

```bash
bash testScripts/run_main_figures
```

runs the Figure 3, Figure 4, and Figure 5 experiment runners in sequence using
their practical default reproduction settings.

These defaults intentionally use fewer measured samples than the full
paper-scale campaigns so that users can validate the build, authentication
profiles, network configuration, and result-processing pipeline in a reasonable
amount of time.

For the published end-to-end evaluation, the paper uses 5,000 measured SSH
handshakes per configuration. Each figure-specific README explains how to invoke
the corresponding runner with the paper-scale measurement count.

Published numerical results are stored separately in the
`published_results.md` file of each figure directory. Locally generated
`results/` files represent a new reproduction run and should not be confused
with the published measurements.

## Extended Evaluation

### Network Sensitivity

Directory:

```text
testScripts/network_sensitivity/
```

Entry point:

```bash
bash testScripts/network_sensitivity/run --mode all
```

Individual modes can be selected with:

```bash
bash testScripts/network_sensitivity/run --mode rtt
bash testScripts/network_sensitivity/run --mode loss
```

The two sub-experiments are:

- `rtt_scan/` — end-to-end handshake latency across configured RTTs from
  0 to 200 ms
- `loss/` — end-to-end handshake behavior under random packet loss

These experiments correspond to the extended evaluation reported in the arXiv
version.

### Concurrency

Directory:

```text
testScripts/concurrency/
```

Entry point:

```bash
bash testScripts/concurrency/run
```

The concurrency evaluation contains two complementary sub-experiments:

- `throughput_cgroup/` — full-SSH server throughput under controlled CPU and
  memory resources using cgroup v2
- `pending_memory/` — server memory growth while KEMUAuth authentication
  challenges remain simultaneously pending

Some concurrency experiments require the
`KEM_TEST_INSTRUMENTATION` build option and cgroup v2 support.

See the README files under `testScripts/concurrency/` for experiment-specific
requirements.

## Implementation Checks

### Ciphertext Robustness

Directory:

```text
testScripts/implementation_checks/ciphertext_robustness/
```

Entry point:

```bash
bash testScripts/implementation_checks/ciphertext_robustness/run
```

This check evaluates malformed-ciphertext handling and related timing behavior
of the KEMUAuth implementation.

The protocol-level check uses the `KEM_TEST_MUTATION` instrumentation
integrated into this branch. The runner temporarily rebuilds the required
server binaries with that flag and restores the normal server binaries after
the check.

This directory is intended for implementation validation rather than
performance benchmarking.

## Shared Experiment Infrastructure

The directory:

```text
testScripts/backends/
```

contains shared backend runners and helper scripts used by the figure-specific
and extended experiments.

These files are implementation infrastructure and normally do not need to be
invoked directly. Users should prefer the experiment-specific entry points
documented above.

## Reproduction Conventions

The repository distinguishes between three types of data:

1. **Published results**

   Files named:

   ```text
   published_results.md
   ```

   record numerical values reported in the paper.

2. **Local reproduction results**

   Files generated under experiment-specific:

   ```text
   results/
   ```

   directories correspond to a new local execution and may differ slightly from
   the published measurements because of hardware, CPU behavior, operating-system
   state, scheduling, and background load.

3. **Quick reproduction settings**

   Some runners use reduced sample counts or shortened timing parameters for
   practical validation. Experiment-specific README files document the
   corresponding published configuration when it differs from the defaults.

## Environment and Privileges

The published evaluation used Ubuntu 22.04.5 LTS, GCC 11.4 with
`-O2 -mavx2`, liboqs 0.15.0, and OpenSSL 3.0.2.

Experiments that configure RTT, packet loss, loopback MTU, or TCP initial
congestion windows require root or `sudo` privileges because they use Linux
networking facilities such as `tc/netem` and `ip route`.

Several experiments launch dedicated local `sshd` instances for measurement.
They do not replace the system SSH daemon.

## Further Documentation

Each experiment directory contains its own README with the exact configuration,
runtime parameters, expected output files, and experiment-specific operational
requirements.

For reproducing a particular paper result, use the corresponding
figure-specific or extended-evaluation README rather than invoking shared
backend scripts directly.
