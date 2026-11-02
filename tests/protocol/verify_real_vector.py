
#!/usr/bin/env python3

import hashlib
import hmac
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORK = HERE / "vector-work"

vector = json.loads(
    (HERE / "mlkem768-vector.json").read_text(encoding="utf-8")
)
fields = vector["fields"]


def ssh_string(data):
    return struct.pack(">I", len(data)) + data


def ssh_text(s):
    return ssh_string(s.encode("utf-8"))


def get(name):
    entry = fields[name]
    data = bytes.fromhex(entry["hex"])
    assert len(data) == entry["length"], name
    assert hashlib.sha256(data).hexdigest() == entry["sha256"], name
    return data


def check(name, expected):
    assert get(name) == expected, f"{name} differs"


def main():
    assert vector["profile"] == "ssh-mlkem-768-hmac-sha256"
    assert vector["public_key_format"] == "ssh-mlkem-768"
    assert vector["user"] == "alice"
    assert vector["service"] == "ssh-connection"
    assert vector["method"] == "publickey-kem"

    # Check every JSON field's length and digest.
    for name in fields:
        get(name)

    # Check source files against the published vector.
    for name in ("d", "z", "m", "sid", "ek", "ct", "K_C"):
        check(name, (WORK / f"{name}.bin").read_bytes())

    ek = get("ek")
    ct = get("ct")
    sid = get("sid")
    secret = get("K_C")

    blob = (
        ssh_text("ssh-mlkem-768")
        + ssh_string(ek)
    )

    request = (
        bytes([50])
        + ssh_text("alice")
        + ssh_text("ssh-connection")
        + ssh_text("publickey-kem")
        + ssh_text(vector["profile"])
        + ssh_string(blob)
    )

    challenge = (
        bytes([60])
        + ssh_text(vector["profile"])
        + ssh_string(blob)
        + ssh_string(ct)
    )

    ctx = request + challenge + bytes([61])

    mac_input = (
        b"ssh-publickey-kem-client-auth"
        + ssh_string(sid)
        + ctx
    )

    ca = hmac.new(secret, mac_input, hashlib.sha256).digest()
    response = bytes([61]) + ssh_string(ca)

    expected = {
        "public_key_blob": blob,
        "request": request,
        "challenge": challenge,
        "ctx": ctx,
        "MAC_input": mac_input,
        "ca": ca,
        "response": response,
    }

    for name, value in expected.items():
        check(name, value)

    # Compare independent Python values with C outputs.
    assert (WORK / "mac_input_c.bin").read_bytes() == mac_input
    assert (WORK / "ca_c.bin").read_bytes() == ca

    assert len(blob) == 1205
    assert len(request) == 1283
    assert len(challenge) == 2331
    assert len(mac_input) == 3680
    assert len(ca) == 32
    assert len(response) == 37

    print("PASS: real ML-KEM-768 vector verification")
    print("  JSON integrity: PASS")
    print("  SSH wire encoding: PASS")
    print("  C/Python MAC_input equality: PASS")
    print("  C/Python HMAC equality: PASS")
    print(f"  ca: {ca.hex()}")


if __name__ == "__main__":
    main()
