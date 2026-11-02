# KEMUAuth

KEMUAuth is an experimental OpenSSH-based reference implementation of the `publickey-kem` SSH user authentication method specified in [draft-liu-sshm-kem-userauth-00](https://datatracker.ietf.org/doc/draft-liu-sshm-kem-userauth/).

## 1. Overview

KEMUAuth replaces the client signature proof in SSH user authentication with a KEM challenge-response exchange. The server encapsulates a shared secret to an authorized client KEM public key, and the client demonstrates possession of the corresponding private key by returning a session-bound HMAC confirmation.

The method preserves SSH transport key exchange and server host authentication.

## 2. Specification

This implementation targets **`draft-liu-sshm-kem-userauth-00`** and its `publickey-kem` authentication method.

The draft defines the protocol messages, wire encodings, algorithm identifiers, confirmation computation, and authentication state requirements. It serves as the protocol specification, while this repository provides a working implementation based on OpenSSH.

## 3. Implementation Scope

The client and server support three authentication profiles:

| Profile | KEM |
| --- | --- |
| `ssh-mlkem-512-hmac-sha256` | ML-KEM-512 |
| `ssh-mlkem-768-hmac-sha256` | ML-KEM-768 |
| `ssh-mlkem-1024-hmac-sha256` | ML-KEM-1024 |

ML-KEM-768 is the draft's recommended (`SHOULD`) profile and is used for the deterministic interoperability test vector in Appendix A. All three profiles are supported by the implementation and covered by the integration tests.

Relevant OpenSSH configuration options include:

- `KEMAuthentication` — enables or disables KEM-based user authentication.
- `KEMAuthAlgorithms` — specifies permitted authentication profiles.
- `IdentityKEMFile` — specifies the client's KEM identity file.
- `AuthorizedKEMKeysFile` — specifies the server's authorized KEM public keys.

The implementation integrates with OpenSSH's `AuthenticationMethods` policy. KEMUAuth can be required as an authentication method or coexist with conventional SSH public-key authentication.

KEM identity files use a three-line text format containing `algorithm`, `public` (Base64), and `secret` (Base64). Server authorization entries use the format `<profile> <Base64 raw public key>`. These are implementation-specific credential formats rather than SSH wire encodings. Identity files contain private key material and should be stored securely.

## 4. Build

The implementation has been tested on Ubuntu 22.04 under WSL2. Building requires a Linux development environment, OpenSSL development headers, liboqs, and standard C build tools.

On Ubuntu, common prerequisites can be installed with:

```sh
sudo apt-get install -y autoconf automake libtool make gcc g++ \
    pkg-config libssl-dev zlib1g-dev python3 iproute2
```

From the repository root, prepare liboqs and build the modified OpenSSH implementation:

```sh
LIBOQS_BRANCH=0.15.0 bash oqs-scripts/clone_liboqs.sh
bash oqs-scripts/build_liboqs.sh
bash oqs-scripts/build_openssh.sh
make ssh sshd sshd-session sshd-auth ssh-keygen
```

The build uses repository-local source and libraries. The integration tests run the locally built SSH binaries without installing or replacing the system SSH service.

## 5. Quick Start

The simplest way to run KEMUAuth is through the automated integration suite:

```sh
bash tests/integration/run.sh
```

The script generates temporary credentials for all three ML-KEM profiles, prepares an Ed25519 server host key and authorization files, and launches an isolated SSH server on `127.0.0.1:42222`.

It then performs the authentication tests, records the results, and stops the test server. The port can be changed using `KEMUAUTH_TEST_PORT`. The tests run locally without root privileges.

For examples of manual client and server configuration, see the `sshd_config` generation and SSH client invocations in `tests/integration/run.sh`.

## 6. Testing

Run all maintained tests from the repository root:

```sh
bash tests/run.sh
```

Individual test categories can also be selected:

```sh
bash tests/run.sh --vectors
bash tests/run.sh --integration
```

**Protocol vectors.** The vector suite verifies the deterministic ML-KEM-768 example in Appendix A of the draft. It checks SSH message encoding, confirmation input construction, and HMAC-SHA256 computation using C and Python implementations.

The reference data is stored in `tests/protocol/mlkem768-vector.json`. The vector can also be regenerated for future draft revisions using the corresponding Makefile target.

**Integration tests.** The integration suite covers successful authentication with all three ML-KEM profiles, unauthorized-key rejection, incorrect confirmation rejection, authentication policy enforcement, permitted fallback, authorization revocation, and Challenge cancellation.

Generated credentials, temporary programs, configurations, and logs are stored under the Git-ignored `tests/integration/.work/` directory.

See [tests/README.md](tests/README.md) for the complete test descriptions and commands.

## 7. Limitations

This implementation focuses on protocol correctness and basic SSH interoperability. The current tests cover the modified OpenSSH client and server, including selected authentication failure and state-management scenarios.

Independent cross-implementation interoperability, extensive performance evaluation, comprehensive security testing, and production deployment hardening are outside the current scope. SSH agent and certificate integration, as well as broader multi-factor authentication combinations, have not been comprehensively evaluated.

The implementation is intended for protocol research and interoperability evaluation rather than production deployment.

## 8. History, Citation and License

The original KEMUAuth implementation was developed for the IEEE ICNP 2026 paper *A Drop-in KEM Replacement for Client Signatures in Post-Quantum SSH*.

The earlier research and evaluation versions remain available through Git history:

- `paper/icnp-2026` — the ICNP 2026 evaluation branch.
- `icnp-2026-paper-release` — the public paper-release tag.
- `icnp-2026-original-artifact` — the original research artifact.

The current implementation focuses on the Internet-Draft and its interoperability tests, while the historical versions preserve the original experimental work.

This repository incorporates OpenSSH / OQS-OpenSSH and related components. See [LICENCE](LICENCE) and the individual source-file notices for applicable licenses.
