# Server-Side Concurrency Evaluation

This directory contains the server-side concurrency experiments reported in the
extended version of:

> **A Drop-in KEM Replacement for Client Signatures in Post-Quantum SSH**
> IEEE ICNP 2026.

The evaluation contains two complementary experiments:

1. concurrent full-SSH throughput and aggregate server-resource consumption;
2. memory scaling under simultaneously pending authentication state.

The first experiment measures whole-server behavior under sustained concurrent
connection load. The second isolates the additional state associated with
pending KEMUAuth challenges.

## Directory Structure

| Directory | Experiment | Published Results |
|:---|:---|:---|
| `throughput_cgroup/` | Concurrent SSH throughput, server CPU cost, tail latency, and aggregate memory | [`published_results.md`](throughput_cgroup/published_results.md) |
| `pending_memory/` | Memory scaling under pending KEMUAuth and ML-DSA-65 authentication state | [`published_results.md`](pending_memory/published_results.md) |

Each subdirectory contains its own runner, analyzer, documentation, and
published reference results.

## Top-Level Runner

Run both concurrency experiments with:

```bash
bash testScripts/concurrency/run
```

Individual experiments can be selected with:

```bash
bash testScripts/concurrency/run --mode throughput
bash testScripts/concurrency/run --mode pending
bash testScripts/concurrency/run --mode all
```

The top-level runner invokes the individual experiment runners with root
privileges where required.

## Concurrent Server Throughput

The throughput experiment is located in:

```text
testScripts/concurrency/throughput_cgroup/
```

It compares KEMUAuth with ML-DSA-65 under concurrent full SSH connection load.

The published experiment evaluates concurrency levels:

```text
1 8 16 32 64
```

with five independent runs per configuration.

The complete `sshd` process tree is restricted to a dedicated two-core cgroup
v2 CPU set, while client workers use a disjoint CPU set.

The experiment reports:

- successful connection throughput;
- server CPU utilization;
- CPU time per successful connection;
- 95th-percentile connection latency;
- aggregate peak server memory.

See:

```text
testScripts/concurrency/throughput_cgroup/README.md
```

for the complete methodology and reproduction instructions.

## Pending Authentication State Memory

The pending-state experiment is located in:

```text
testScripts/concurrency/pending_memory/
```

It artificially holds authentication attempts at corresponding authentication
stages so that multiple connections remain simultaneously pending.

KEMUAuth and ML-DSA-65 are fitted independently using the actually observed
pending or paused connection count from each run. The fitted models are then
evaluated at common normalized values of `P`.

The experiment distinguishes ordinary OpenSSH per-connection memory growth from
the explicitly retained KEMUAuth challenge state.

See:

```text
testScripts/concurrency/pending_memory/README.md
```

for the complete methodology, instrumentation requirements, and analysis
procedure.

## Requirements

Both experiments require:

- Linux;
- a KEMUAuth-enabled OpenSSH build;
- ML-KEM-768 KEMUAuth support;
- ML-DSA-65 public-key authentication support;
- `mlkem768x25519-sha256` transport KEX support;
- Python 3 for result analysis.

The throughput experiment additionally requires cgroup v2, root privileges,
and CPU-affinity support.

The pending-state experiment additionally requires cgroup v2, root privileges,
and a build with `KEM_TEST_INSTRUMENTATION` enabled.

The pending-state instrumentation is already integrated into this paper branch
and is disabled in normal builds. No additional source patch is required.

## Published Results vs. Local Runs

The `published_results.md` files preserve the numerical values reported in the
extended paper.

New local measurements are written beneath each experiment's `results/`
directory and do not overwrite the published reference values.

Local results may vary with hardware, CPU topology, operating-system
scheduling, software versions, and system load.
