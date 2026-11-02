
#!/usr/bin/env python3

import base64
import os
from pathlib import Path

WORK = Path("tests/integration/.work")

PROFILES = {
    512: (800, 1632),
    768: (1184, 2400),
    1024: (1568, 3168),
}


def main():
    authorized = []

    for level, (pk_len, sk_len) in PROFILES.items():
        path = WORK / f"id_mlkem{level}"
        expected_alg = f"ssh-mlkem-{level}-hmac-sha256"

        fields = {}

        for line in path.read_text().splitlines():
            name, value = line.split(None, 1)

            if name in fields:
                raise ValueError(f"Duplicate field: {name}")

            fields[name] = value

        if set(fields) != {"algorithm", "public", "secret"}:
            raise ValueError(f"Unexpected fields in {path}")

        if fields["algorithm"] != expected_alg:
            raise ValueError(f"Incorrect algorithm: {path}")

        public = base64.b64decode(
            fields["public"], validate=True
        )
        secret = base64.b64decode(
            fields["secret"], validate=True
        )

        if len(public) != pk_len or len(secret) != sk_len:
            raise ValueError(f"Incorrect key lengths: {path}")

        if path.stat().st_mode & 0o077:
            raise ValueError(f"Insecure permissions: {path}")

        authorized.append(
            f"{expected_alg} {fields['public']}"
        )

        print(
            f"PASS: ML-KEM-{level} "
            f"(public={len(public)}, secret={len(secret)})"
        )

    # Only public keys are written to the authorization file.
    output = WORK / "authorized_kem_keys"

    output.write_text(
        "\n".join(authorized) + "\n"
    )
    os.chmod(output, 0o600)

    print("PASS: authorization file generated")
    print(f"  Entries: {len(authorized)}")
    print(f"  Output: {output}")


if __name__ == "__main__":
    main()
