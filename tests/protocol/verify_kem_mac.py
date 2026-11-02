
#!/usr/bin/env python3

import hashlib
import hmac
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent


def ssh_string(data: bytes) -> bytes:
    """RFC 4251 SSH string encoding."""
    return struct.pack(">I", len(data)) + data


def text_string(value: str) -> bytes:
    return ssh_string(value.encode("ascii"))


def main():
    # These inputs must match kem_mac_test.c.
    alg = "ssh-mlkem-768-hmac-sha256"
    user = "alice"
    service = "ssh-connection"
    method = "publickey-kem"

    pk = bytes(i & 0xff for i in range(1184))
    ct = bytes((7 * i + 3) & 0xff for i in range(1088))
    sid = bytes(0x40 + i for i in range(32))
    secret = bytes(0xa0 + i for i in range(32))

    # Independently encode the SSH public key blob.
    public_key_blob = (
        text_string("ssh-mlkem-768")
        + ssh_string(pk)
    )

    # SSH_MSG_USERAUTH_REQUEST = 50.
    request = (
        bytes([50])
        + text_string(user)
        + text_string(service)
        + text_string(method)
        + text_string(alg)
        + ssh_string(public_key_blob)
    )

    # SSH_MSG_USERAUTH_KEM_CHALLENGE = 60.
    challenge = (
        bytes([60])
        + text_string(alg)
        + ssh_string(public_key_blob)
        + ssh_string(ct)
    )

    # The last byte is the Response message type (61).
    ctx = request + challenge + bytes([61])

    label = b"ssh-publickey-kem-client-auth"

    mac_input = label + ssh_string(sid) + ctx

    ca = hmac.new(
        secret,
        mac_input,
        hashlib.sha256
    ).digest()

    # Compare all bytes against the OpenSSH C implementation.
    c_mac_input = (HERE / "kem_mac_input.bin").read_bytes()
    c_ca = (HERE / "kem_ca.bin").read_bytes()

    if c_mac_input != mac_input:
        raise SystemExit("FAIL: MAC_input differs from C")

    if c_ca != ca:
        raise SystemExit("FAIL: confirmation value differs from C")

    assert len(public_key_blob) == 1205
    assert len(ca) == 32

    print("PASS: independent Python verification")
    print(f"  MAC_input length: {len(mac_input)} bytes")
    print(f"  MAC_input SHA-256: {hashlib.sha256(mac_input).hexdigest()}")
    print(f"  ca: {ca.hex()}")
    print("  Byte-for-byte comparison: PASS")


if __name__ == "__main__":
    main()
