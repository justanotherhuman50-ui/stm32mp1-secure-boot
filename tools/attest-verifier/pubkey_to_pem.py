#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Convert attest_pubkey output (e=<hex>, n=<hex>) to an RSA public key PEM.
PEM goes to stdout, the SHA-256 SPKI fingerprint to stderr."""
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import verify


def parse(text):
    kv = {}
    for ln in text.splitlines():
        if "=" in ln:
            k, v = ln.strip().split("=", 1)
            kv[k] = v
    for k in ("e", "n"):
        if k not in kv:
            raise ValueError("missing %s= line" % k)
    try:
        return int(kv["e"], 16), int(kv["n"], 16)
    except ValueError:
        raise ValueError("e or n is not hex") from None


def to_pem(e, n):
    pub = rsa.RSAPublicNumbers(e, n).public_key()
    pem = pub.public_bytes(serialization.Encoding.PEM,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return pub, pem


def main():
    text = open(sys.argv[1]).read() if len(sys.argv) > 1 else sys.stdin.read()
    try:
        pub, pem = to_pem(*parse(text))
    except ValueError as ex:
        print("input error: %s" % ex, file=sys.stderr)
        return 2
    sys.stdout.write(pem.decode())
    print("bits=%d key_sha256=%s" % (pub.key_size, verify.key_fingerprint(pub)),
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
