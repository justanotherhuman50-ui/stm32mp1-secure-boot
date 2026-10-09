#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Self-tests for the capstone attestation evidence verifier."""

import hashlib
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

import verify


def make_key(bits=3072):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def make_evidence(priv, nonce, tee_hash, ta_uuid, ta_hash):
    claims = (
        verify.MAGIC
        + (verify.VERSION).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + nonce
        + tee_hash
        + ta_uuid
    )
    digest = verify.compute_digest(nonce, claims, ta_hash)
    sig = priv.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=verify.PSS_SALT_LEN,
        ),
        utils.Prehashed(hashes.SHA256()),
    )
    return (
        claims
        + ta_hash
        + len(sig).to_bytes(2, "big")
        + sig
    )


def expect_value_error(name, fn):
    try:
        fn()
    except ValueError:
        return
    else:
        raise AssertionError(f"{name}: expected ValueError")


def expect_reject(name, fn, reason):
    try:
        fn()
    except verify.VerifyError as exc:
        assert exc.reason == reason, (
            f"{name}: expected {reason}, got {exc.reason}"
        )
    else:
        raise AssertionError(f"{name}: verification unexpectedly succeeded")


def main():
    passed = 0

    def test(name, fn):
        nonlocal passed
        fn()
        passed += 1
        print(f"PASS {name}")

    priv3072 = make_key(3072)
    pub3072 = priv3072.public_key()
    priv2048 = make_key(2048)
    pub2048 = priv2048.public_key()

    nonce = bytes(range(32))
    tee_hash = hashlib.sha256(b"synthetic-optee").digest()
    ta_hash = hashlib.sha256(b"synthetic-ta").digest()
    ta_uuid = verify.TA_UUID

    blob3072 = make_evidence(priv3072, nonce, tee_hash, ta_uuid, ta_hash)

    tee_allow = {tee_hash}
    ta_allow = {ta_hash}

    test("good 3072 evidence", lambda: verify.verify(
        blob3072, nonce, pub3072, tee_allow, ta_allow))

    test("wrong nonce", lambda: expect_reject(
        "wrong nonce",
        lambda: verify.verify(
            blob3072, bytes([x ^ 1 for x in nonce]),
            pub3072, tee_allow, ta_allow),
        "nonce_mismatch"))

    test("short blob", lambda: expect_reject(
        "short blob",
        lambda: verify.verify(
            blob3072[:verify.OFF_SIG - 1], nonce,
            pub3072, tee_allow, ta_allow),
        "truncated"))

    test("long blob", lambda: expect_reject(
        "long blob",
        lambda: verify.verify(
            blob3072 + b"\x00", nonce,
            pub3072, tee_allow, ta_allow),
        "length_mismatch"))

    def bad_magic():
        b = bytearray(blob3072)
        b[0] ^= 1
        verify.verify(bytes(b), nonce, pub3072, tee_allow, ta_allow)

    test("bad magic", lambda: expect_reject(
        "bad magic", bad_magic, "bad_magic"))

    def bad_reserved():
        b = bytearray(blob3072)
        b[6:8] = (1).to_bytes(2, "big")
        verify.verify(bytes(b), nonce, pub3072, tee_allow, ta_allow)

    test("nonzero reserved", lambda: expect_reject(
        "nonzero reserved", bad_reserved, "bad_reserved"))

    def bad_sig_len():
        b = bytearray(blob3072)
        b[verify.OFF_SIG_LEN:verify.OFF_SIG_LEN + 2] = (1).to_bytes(2, "big")
        verify.verify(bytes(b), nonce, pub3072, tee_allow, ta_allow)

    test("signature length mismatch", lambda: expect_reject(
        "signature length mismatch", bad_sig_len, "length_mismatch"))

    for name, offset in (
        ("flipped nonce", verify.OFF_NONCE),
        ("flipped tee_hash", verify.OFF_TEE_HASH),
        ("flipped ta_uuid", verify.OFF_TA_UUID),
        ("flipped ta_hash", verify.OFF_TA_HASH),
        ("flipped signature", verify.OFF_SIG),
    ):
        def tamper(off=offset):
            b = bytearray(blob3072)
            b[off] ^= 1
            verify.verify(bytes(b), nonce, pub3072, tee_allow, ta_allow)

        test(name, lambda tamper=tamper: expect_reject(
            name, tamper,
            "nonce_mismatch" if offset == verify.OFF_NONCE
            else "bad_signature"))

    test("empty tee allowlist", lambda: expect_reject(
        "empty tee allowlist",
        lambda: verify.verify(blob3072, nonce, pub3072, set(), ta_allow),
        "tee_hash_not_allowed"))

    test("empty ta allowlist", lambda: expect_reject(
        "empty ta allowlist",
        lambda: verify.verify(blob3072, nonce, pub3072, tee_allow, set()),
        "ta_hash_not_allowed"))

    wrong_uuid = bytes(16)

    def uuid_mismatch():
        b = make_evidence(priv3072, nonce, tee_hash, wrong_uuid, ta_hash)
        verify.verify(b, nonce, pub3072, tee_allow, ta_allow)

    test("UUID mismatch", lambda: expect_reject(
        "UUID mismatch", uuid_mismatch, "uuid_mismatch"))

    wrong_key = make_key(3072).public_key()

    test("wrong pinned key", lambda: expect_reject(
        "wrong pinned key",
        lambda: verify.verify(
            blob3072, nonce, wrong_key, tee_allow, ta_allow),
        "bad_signature"))

    blob2048 = make_evidence(priv2048, nonce, tee_hash, ta_uuid, ta_hash)

    test("good 2048 evidence", lambda: verify.verify(
        blob2048, nonce, pub2048, tee_allow, ta_allow))

    test("RSA-3072 signature length", lambda: verify.verify(
        blob3072, nonce, pub3072, tee_allow, ta_allow))

    def malformed_pem():
        with tempfile.NamedTemporaryFile() as f:
            f.write(b"not a PEM key")
            f.flush()
            verify.load_pubkey(f.name)

    test("malformed PEM", lambda: (
        expect_value_error("malformed PEM", malformed_pem)
    ))

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)

        good_pem = pub3072.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pem_path = td / "good.pem"
        pem_path.write_bytes(good_pem)

        loaded = verify.load_pubkey(str(pem_path))
        assert loaded.key_size == 3072
        assert verify.key_fingerprint(loaded) == verify.key_fingerprint(pub3072)
        print("PASS load PEM")
        passed += 1

        allow_path = td / "allow.txt"
        allow_path.write_text(
            f"# comment\n\n{tee_hash.hex()}\n{ta_hash.hex()}  # inline\n",
            encoding="utf-8",
        )
        values = verify.load_allowlist(str(allow_path))
        assert values == {tee_hash, ta_hash}
        print("PASS allowlist parsing")
        passed += 1

        bad_allow = td / "bad-allow.txt"
        bad_allow.write_text("abcd\n", encoding="utf-8")
        malformed_allowlist = False
        try:
            verify.load_allowlist(str(bad_allow))
        except ValueError:
            malformed_allowlist = True
        assert malformed_allowlist
        print("PASS malformed allowlist")
        passed += 1

    print(f"\n{passed} tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
