
#!/usr/bin/env python3

import hashlib
import hmac
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "vector-work"
OUTPUT = HERE / "mlkem768-vector.json"


def read_vector(name, length):
    data = (SOURCE / f"{name}.bin").read_bytes()
    if len(data) != length:
        raise ValueError(f"{name}: expected {length} bytes")
    return data


def ssh_string(data):
    return struct.pack(">I", len(data)) + data


def ssh_text(value):
    return ssh_string(value.encode("utf-8"))


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def main():
    # Deterministic FIPS 203 inputs and outputs.
    d = read_vector("d", 32)
    z = read_vector("z", 32)
    m = read_vector("m", 32)
    sid = read_vector("sid", 32)
    ek = read_vector("ek", 1184)
    ct = read_vector("ct", 1088)
    shared_secret = read_vector("K_C", 32)

    # Check the fixed inputs selected for this vector.
    assert d == bytes(range(0x00, 0x20))
    assert z == bytes(range(0x20, 0x40))
    assert m == bytes(range(0x40, 0x60))
    assert sid == bytes(range(0x60, 0x80))

    user = "alice"
    service = "ssh-connection"
    method = "publickey-kem"
    alg = "ssh-mlkem-768-hmac-sha256"
    key_format = "ssh-mlkem-768"
    label = b"ssh-publickey-kem-client-auth"

    # Section 5.2: SSH public key blob.
    public_key_blob = (
        ssh_text(key_format)
        + ssh_string(ek)
    )

    # Section 4.1: initial authentication request.
    request = (
        bytes([50])
        + ssh_text(user)
        + ssh_text(service)
        + ssh_text(method)
        + ssh_text(alg)
        + ssh_string(public_key_blob)
    )

    # Section 4.1: KEM challenge.
    challenge = (
        bytes([60])
        + ssh_text(alg)
        + ssh_string(public_key_blob)
        + ssh_string(ct)
    )

    # Section 4.2: authentication context.
    ctx = request + challenge + bytes([61])

    mac_input = label + ssh_string(sid) + ctx

    # Sections 4.2 and 5.3: full HMAC-SHA256.
    ca = hmac.new(
        shared_secret, mac_input, hashlib.sha256
    ).digest()

    response = bytes([61]) + ssh_string(ca)

    # Check basic structural invariants.
    assert len(public_key_blob) == 1205
    assert len(mac_input) == 3680
    assert len(ca) == 32
    assert len(response) == 37

    fields = {
        "d": d,
        "z": z,
        "m": m,
        "sid": sid,
        "ek": ek,
        "ct": ct,
        "K_C": shared_secret,
        "public_key_blob": public_key_blob,
        "request": request,
        "challenge": challenge,
        "ctx": ctx,
        "MAC_input": mac_input,
        "ca": ca,
        "response": response,
    }

    vector = {
        "description": "KEMUAuth ML-KEM-768 test vector",
        "profile": alg,
        "user": user,
        "service": service,
        "method": method,
        "public_key_format": key_format,
        "fields": {
            name: {
                "length": len(data),
                "hex": data.hex(),
                "sha256": sha256(data),
            }
            for name, data in fields.items()
        },
    }

    OUTPUT.write_text(
        json.dumps(vector, indent=2) + "\n",
        encoding="utf-8",
    )

    print("PASS: draft vector generated")
    print(f"  Public key blob: {len(public_key_blob)} bytes")
    print(f"  Request: {len(request)} bytes")
    print(f"  Challenge: {len(challenge)} bytes")
    print(f"  MAC_input: {len(mac_input)} bytes")
    print(f"  ek SHA-256: {sha256(ek)}")
    print(f"  ct SHA-256: {sha256(ct)}")
    print(f"  MAC_input SHA-256: {sha256(mac_input)}")
    print(f"  K_C: {shared_secret.hex()}")
    print(f"  ca: {ca.hex()}")
    print(f"  Output: {OUTPUT}")


if __name__ == "__main__":
    main()
