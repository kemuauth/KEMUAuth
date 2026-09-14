# KEMUAuth: KEM-Based Client Authentication for Post-Quantum SSH

KEMUAuth is a research implementation of **KEM-based client authentication for
SSH**. It replaces signature-based client proof of possession with a KEM-based
challenge-response mechanism while preserving the existing SSH transport
handshake and the overall SSH user-authentication framework.

This repository contains the OpenSSH-based implementation, build infrastructure,
and evaluation scripts associated with the paper:

> **A Drop-in KEM Replacement for Client Signatures in Post-Quantum SSH**
> Accepted at IEEE ICNP 2026.

## Repository Status

This branch is the **paper-aligned ICNP 2026 implementation**.

It is intended to preserve the implementation and evaluation environment
corresponding to the camera-ready paper and the extended arXiv version. The
experiment organization, published numerical results, and reproduction
instructions in this branch are maintained to match the published work.

Two narrowly scoped post-artifact robustness hardening changes are present in
this branch: explicit client-side KEM ciphertext-length validation and safer
test-only malformed-ciphertext mutation instrumentation. These changes do not
alter the valid KEMUAuth protocol flow. The original ICNP artifact
implementation is preserved by the tag `icnp-2026-original-artifact`.

Future standards-oriented development may refine protocol details, wire
formats, algorithm negotiation, implementation structure, and testing
infrastructure. Such development should take place on the project's main
development branch rather than modifying the historical paper-aligned behavior
in this branch.

## KEMUAuth Overview

The KEMUAuth client-authentication method follows the SSH public-key
authentication structure but replaces the client's signature proof with a
KEM-based proof of possession.

At a high level:

1. The client advertises a KEM public key and KEMUAuth algorithm.
2. The server encapsulates to the registered client KEM public key and returns
   the resulting ciphertext as an authentication challenge.
3. The client decapsulates the ciphertext and derives an authentication
   response from the resulting shared secret and session-bound context.
4. The server verifies the response and accepts the client authentication if
   the proof is valid.

The implementation is integrated at the SSH user-authentication layer and does
not replace the SSH transport key exchange.

The primary SSH authentication method implemented in this repository is:

```text
publickey-kem
```

The source tree also contains experimental hybrid authentication paths used by
the paper's migration evaluation.

## Source-Code Map

The most relevant KEMUAuth implementation files include:

```text
ssh-kem.c
ssh-kem.h
auth2-kem.c
auth2-kem.h
```

Client-side SSH integration is implemented in the modified OpenSSH client
authentication path, while server-side processing is integrated into the
OpenSSH user-authentication subsystem.

The remainder of the repository contains the underlying OpenSSH/OQS-OpenSSH
source tree and supporting build infrastructure.

## Repository Layout

```text
.
├── ssh-kem.c / ssh-kem.h
│   └── Shared KEMUAuth/KEM support
├── auth2-kem.c / auth2-kem.h
│   └── Server-side KEMUAuth user authentication
├── oqs-scripts/
│   └── liboqs and OpenSSH build helpers
├── testScripts/
│   ├── figure3/
│   ├── figure4/
│   ├── figure5/
│   ├── concurrency/
│   ├── network_sensitivity/
│   ├── implementation_checks/
│   └── backends/
└── README.md
```

For experiment-specific documentation, see:

```text
testScripts/README.md
```

## Build Environment

The paper evaluation environment uses:

- Ubuntu 22.04.5 LTS
- GCC 11.4
- OpenSSL 3.0.2
- liboqs 0.15.0
- AVX2-enabled compilation where supported

A Linux environment is strongly recommended. Several evaluation scripts also
require `sudo` privileges for Linux network configuration.

### Install Build Dependencies

On Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y \
  autoconf \
  automake \
  libtool \
  make \
  gcc \
  g++ \
  pkg-config \
  libssl-dev \
  zlib1g-dev
```

### Build liboqs

From the repository root:

```bash
LIBOQS_BRANCH=0.15.0 bash oqs-scripts/clone_liboqs.sh
bash oqs-scripts/build_liboqs.sh
```

The repository-local liboqs installation is placed under:

```text
oqs/
```

### Build KEMUAuth / OQS-OpenSSH

Run:

```bash
bash oqs-scripts/build_openssh.sh
```

After a successful build, KEMUAuth-enabled OpenSSH binaries such as:

```text
ssh
sshd
ssh-keygen
```

are available from the repository build tree.

A successful KEMUAuth build can also be checked with:

```bash
grep WITH_OQS config.h
```

and by inspecting the supported OpenSSH algorithms.

## Paper Reproduction

The evaluation scripts are organized according to the final paper rather than
the internal experiment numbering used during development.

### Figure 3 — Client-Authentication Algorithm Comparison

```bash
sudo bash testScripts/figure3/run
```

Figure 3 compares classical signatures, post-quantum signatures, KEMUAuth
configurations, and the password baseline under a fixed network environment.

Documentation:

```text
testScripts/figure3/README.md
```

Published paper values:

```text
testScripts/figure3/published_results.md
```

### Figure 4 — Migration Configurations across RTT Regimes

```bash
bash testScripts/figure4/run
```

Figure 4 evaluates eight client/server authentication migration configurations
under approximately 37 ms, 67 ms, and 163 ms RTTs.

The paper-aligned runner explicitly selects the combined classical/post-quantum
authentication paths used by the hybrid configurations.

Documentation:

```text
testScripts/figure4/README.md
```

Published paper values:

```text
testScripts/figure4/published_results.md
```

### Figure 5 — TCP Initial-Window Sensitivity

```bash
bash testScripts/figure5/run
```

Figure 5 studies authentication-object transmission effects by varying the TCP
initial congestion window over:

```text
3 5 7 10 15 20 25 30 35 40 50 MSS
```

Documentation:

```text
testScripts/figure5/README.md
```

Published paper values:

```text
testScripts/figure5/published_results.md
```

### Run the Three Main Figure Experiments

The main paper experiment runners can be invoked sequentially with:

```bash
bash testScripts/run_main_figures
```

The default runners intentionally use reduced sample counts so that users can
validate the build, authentication configuration, networking setup, and
result-processing pipeline without immediately executing the complete
paper-scale campaign.

The paper-scale end-to-end measurements use 5,000 measured SSH handshakes per
configuration. See each figure-specific README for the corresponding
reproduction command and experiment-specific settings.

## Published Results and Local Reproduction

The repository distinguishes between the numerical results reported in the
paper and results generated by a new local execution.

Files named:

```text
published_results.md
```

contain the canonical values reported in the paper.

Files generated under experiment-specific:

```text
results/
```

directories represent a new local reproduction run.

Timing measurements may vary across machines because of hardware, CPU
frequency, kernel behavior, scheduling, system load, and networking
configuration. The published values therefore serve as reference measurements,
not platform-independent performance guarantees.

## Extended Evaluation

The extended evaluation is organized independently from the three main figure
experiments.

### Concurrency

```text
testScripts/concurrency/
```

This evaluation studies server-side behavior under concurrent KEMUAuth
connections, including:

```text
throughput_cgroup/
pending_memory/
```

Entry point:

```bash
bash testScripts/concurrency/run
```

Some concurrency measurements require cgroup v2 and the
`KEM_TEST_INSTRUMENTATION` build option.

### Network Sensitivity

```text
testScripts/network_sensitivity/
```

This evaluation contains:

```text
rtt_scan/
loss/
```

and studies handshake behavior across a denser RTT range and under random
packet loss.

Entry point:

```bash
bash testScripts/network_sensitivity/run --mode all
```

Individual modes are available through:

```bash
bash testScripts/network_sensitivity/run --mode rtt
bash testScripts/network_sensitivity/run --mode loss
```

### Ciphertext Robustness

```text
testScripts/implementation_checks/ciphertext_robustness/
```

This implementation check evaluates malformed-ciphertext handling and related
timing behavior.

Entry point:

```bash
bash testScripts/implementation_checks/ciphertext_robustness/run
```

It requires the `KEM_TEST_MUTATION` build option.

Detailed requirements and result descriptions for these evaluations are
documented under their respective directories.

## Runtime Workspaces

Some experiment scripts generate temporary SSH/KEM identities and runtime
configuration files.

In particular:

```text
testScripts/.work-kem/
```

is used as a local runtime workspace for generated KEM identity material.

Runtime workspaces are excluded by `.gitignore` and must not be committed to
the repository.

## Project and Artifact History

The initial public implementation was released through an anonymous GitHub
account during the paper-review process.

This repository is the maintained KEMUAuth project repository and preserves the
historical relationship to that research artifact. The paper-aligned branch
contains the cleaned and documented version of the implementation corresponding
to the ICNP 2026 paper, while future protocol and standards-oriented development
can evolve independently on the main development branch.

The original anonymous artifact should be treated as a historical snapshot.
For current project documentation, reproducibility instructions, and future
development, use this repository.

## Reproducibility Notes

Network-sensitive experiments use Linux facilities such as:

```text
tc/netem
ip route
```

and therefore commonly require root or `sudo` privileges.

The evaluation scripts launch dedicated local SSH server instances for
measurement and do not replace the host system's SSH daemon.

Temporary keys, runtime configuration, and locally reproduced results should
not be interpreted as source artifacts or published measurements.

## Citation

If you use KEMUAuth in academic work, please cite:

> **A Drop-in KEM Replacement for Client Signatures in Post-Quantum SSH**
> IEEE ICNP 2026.

Complete proceedings metadata and persistent publication identifiers can be
added here once the final bibliographic record is available.

## License

This repository incorporates and modifies OpenSSH/OQS-OpenSSH source code and
includes components distributed under their respective licenses.

See:

```text
LICENCE
```

and the upstream source headers for the applicable licensing terms.
