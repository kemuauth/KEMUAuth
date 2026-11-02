# KEMUAuth Tests

This directory contains the protocol test vectors and integration tests for the KEMUAuth implementation corresponding to `draft-liu-sshm-kem-userauth-00`.

Run the complete test suite from the repository root:

```sh
bash tests/run.sh
```

Alternatively, select a specific category:

```sh
bash tests/run.sh --vectors
bash tests/run.sh --integration
```

## ML-KEM-768 Draft Test Vector

`tests/protocol/mlkem768-vector.json` contains the deterministic interoperability test vector specified in Appendix A of the draft.

The JSON file preserves the complete test inputs and derived values, including the ML-KEM public key, ciphertext, shared secret, SSH-encoded messages, confirmation input, and expected confirmation value. Only the recommended ML-KEM-768 profile has a published deterministic vector.

The vector test regenerates the deterministic inputs and verifies the results using the locally built liboqs and OpenSSH libraries. It also performs independent C/Python checks of SSH encoding and HMAC computation.

```sh
bash tests/run.sh --vectors
```

For future draft revisions that modify the vector definition, an updated JSON vector can be generated with:

```sh
make -f Makefile -f tests/protocol/Makefile.kem-blob kem-vector-regenerate
```

The resulting values can be compared with the corresponding draft specification using:

```sh
git diff -- tests/protocol/mlkem768-vector.json
```

## Integration Suite

The integration suite launches an isolated local SSH server and runs nine authentication and policy checks:

1. Successful ML-KEM-512 authentication.
2. Successful ML-KEM-768 authentication.
3. Successful ML-KEM-1024 authentication.
4. Rejection of an unauthorized ML-KEM-768 public key.
5. Rejection of an incorrect ML-KEM-768 confirmation generated from mismatched key material.
6. Enforcement of a server policy requiring KEMUAuth.
7. Conventional SSH public-key authentication when explicitly permitted.
8. Rejection when public-key authorization is revoked after the KEM Challenge.
9. Cancellation of a pending KEM Challenge following another authentication request.

Run the suite with:

```sh
bash tests/run.sh --integration
```

By default, the server listens on `127.0.0.1:42222`. The port can be configured through `KEMUAUTH_TEST_PORT`.

The authorization-revocation test uses a test-only helper to pause client decapsulation while the server's authorization file is updated. The Challenge-cancellation test uses a temporary modified SSH client to trigger a new authentication request during an outstanding KEM exchange.

These tests exercise the corresponding implementation paths. The incorrect-confirmation test uses mismatched key material rather than arbitrary malformed packets, and the cancellation test verifies Monitor state cancellation without directly replaying a previous Response.

Temporary credentials, configurations, test binaries, and logs are stored in `tests/integration/.work/`, which is excluded from Git tracking.
