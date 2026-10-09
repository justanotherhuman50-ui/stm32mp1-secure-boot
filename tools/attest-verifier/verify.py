#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Verifier for the capstone attestation evidence, format v1.

Evidence layout (big-endian, fixed size, no padding), see attestation_ta.h:
  0   4  magic "RAT1"
  4   2  version = 1
  6   2  reserved = 0
  8  32  verifier nonce, echoed back
  40 32  tee_hash (OP-TEE measurement, PTA 0x3)
  72 16  TA UUID (RFC 4122 byte order)
  88 32  ta_hash (TA measurement, PTA 0x2)
  120 2  sig_len
  122 .. signature
Claims are bytes 0..87.

Digest chain (must match the TA and the attestation PTA):
  claims_hash = SHA256(claims)
  nonce2      = SHA256(nonce || claims_hash)
  digest      = SHA256(nonce2 || ta_hash)
The PTA signs `digest` with RSASSA-PKCS1-PSS, MGF1-SHA256, salt length 32,
treating `digest` as an already computed hash. It is verified PREHASHED here:
hashing it again is the classic failure mode.

Check order: structure, nonce, signature, then policy (UUID, allowlists).
Policy fields are only trusted after the signature has verified. Allowlists
have no default: an empty or missing list rejects everything (fail closed).

Trust anchor: the caller pins the device public key out of band. This tool
does not do trust-on-first-use.

Exit codes: 0 valid, 1 rejected, 2 bad input or usage.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import struct
import sys
import uuid as uuid_mod
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

MAGIC = b"RAT1"
VERSION = 1
NONCE_LEN = 32
HASH_LEN = 32
UUID_LEN = 16

OFF_VERSION = 4
OFF_RESERVED = 6
OFF_NONCE = 8
OFF_TEE_HASH = 40
OFF_TA_UUID = 72
CLAIMS_LEN = 88
OFF_TA_HASH = CLAIMS_LEN
OFF_SIG_LEN = OFF_TA_HASH + HASH_LEN
OFF_SIG = OFF_SIG_LEN + 2

PSS_SALT_LEN = 32
TA_UUID = uuid_mod.UUID("6e6c47cd-0a2e-4e8a-b15b-b08469dbae06").bytes


class VerifyError(Exception):
    """Rejection with a stable machine-readable reason code."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


@dataclass(frozen=True)
class Evidence:
    claims: bytes
    nonce: bytes
    tee_hash: bytes
    ta_uuid: bytes
    ta_hash: bytes
    sig: bytes


def parse(blob: bytes) -> Evidence:
    """Strict structural parse. No cryptography here."""
    if len(blob) < OFF_SIG:
        raise VerifyError("truncated",
                          f"{len(blob)} bytes, need at least {OFF_SIG}")
    if blob[0:4] != MAGIC:
        raise VerifyError("bad_magic", blob[0:4].hex())
    (version,) = struct.unpack_from(">H", blob, OFF_VERSION)
    if version != VERSION:
        raise VerifyError("bad_version", str(version))
    (reserved,) = struct.unpack_from(">H", blob, OFF_RESERVED)
    if reserved != 0:
        raise VerifyError("bad_reserved", str(reserved))
    (sig_len,) = struct.unpack_from(">H", blob, OFF_SIG_LEN)
    if sig_len == 0:
        raise VerifyError("bad_sig_len", "0")
    if len(blob) != OFF_SIG + sig_len:
        raise VerifyError("length_mismatch",
                          f"sig_len {sig_len} implies {OFF_SIG + sig_len} "
                          f"bytes, got {len(blob)}")
    return Evidence(
        claims=blob[0:CLAIMS_LEN],
        nonce=blob[OFF_NONCE:OFF_NONCE + NONCE_LEN],
        tee_hash=blob[OFF_TEE_HASH:OFF_TEE_HASH + HASH_LEN],
        ta_uuid=blob[OFF_TA_UUID:OFF_TA_UUID + UUID_LEN],
        ta_hash=blob[OFF_TA_HASH:OFF_TA_HASH + HASH_LEN],
        sig=blob[OFF_SIG:],
    )


def compute_digest(nonce: bytes, claims: bytes, ta_hash: bytes) -> bytes:
    claims_hash = hashlib.sha256(claims).digest()
    nonce2 = hashlib.sha256(nonce + claims_hash).digest()
    return hashlib.sha256(nonce2 + ta_hash).digest()


def key_fingerprint(pub: rsa.RSAPublicKey) -> str:
    """SHA-256 of the DER SubjectPublicKeyInfo, hex."""
    der = pub.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def verify(blob: bytes, expected_nonce: bytes, pubkey: rsa.RSAPublicKey,
           tee_allow: "set[bytes]", ta_allow: "set[bytes]",
           expected_uuid: bytes = TA_UUID) -> Evidence:
    """Return the parsed evidence, or raise VerifyError."""
    if len(expected_nonce) != NONCE_LEN:
        raise ValueError(f"expected nonce must be {NONCE_LEN} bytes")
    ev = parse(blob)

    if not hmac.compare_digest(ev.nonce, expected_nonce):
        raise VerifyError("nonce_mismatch")

    modulus_len = (pubkey.key_size + 7) // 8
    if len(ev.sig) != modulus_len:
        raise VerifyError("sig_len_key_mismatch",
                          f"sig {len(ev.sig)} bytes, key modulus "
                          f"{modulus_len} bytes")

    digest = compute_digest(expected_nonce, ev.claims, ev.ta_hash)
    try:
        pubkey.verify(
            ev.sig, digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=PSS_SALT_LEN),
            utils.Prehashed(hashes.SHA256()))
    except InvalidSignature:
        raise VerifyError("bad_signature") from None

    # Signature verified: the claims below are now authenticated.
    if ev.ta_uuid != expected_uuid:
        raise VerifyError("uuid_mismatch", ev.ta_uuid.hex())
    if ev.tee_hash not in tee_allow:
        raise VerifyError("tee_hash_not_allowed", ev.tee_hash.hex())
    if ev.ta_hash not in ta_allow:
        raise VerifyError("ta_hash_not_allowed", ev.ta_hash.hex())
    return ev


def load_allowlist(path: str) -> "set[bytes]":
    """One 64-hex-char SHA-256 per line; '#' starts a comment."""
    out = set()
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                h = bytes.fromhex(line)
            except ValueError:
                raise ValueError(f"{path}:{lineno}: not hex") from None
            if len(h) != HASH_LEN:
                raise ValueError(f"{path}:{lineno}: expected "
                                 f"{2 * HASH_LEN} hex chars")
            out.add(h)
    return out


def load_pubkey(path: str) -> rsa.RSAPublicKey:
    with open(path, "rb") as f:
        key = serialization.load_pem_public_key(f.read())
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError(f"{path}: not an RSA public key")
    return key


def extract_evidence(text: str) -> bytes:
    """Accept the CA's stdout ('evidence=<hex>' line) or bare hex."""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    for ln in lines:
        if ln.startswith("evidence="):
            return bytes.fromhex(ln[len("evidence="):])
    return bytes.fromhex("".join(lines))


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--pubkey", required=True,
                    help="pinned device public key (PEM, RSA)")
    ap.add_argument("--nonce", required=True,
                    help="the 32-byte nonce YOU sent, as 64 hex chars")
    ap.add_argument("--tee-allow", required=True,
                    help="allowlist file of accepted tee_hash values")
    ap.add_argument("--ta-allow", required=True,
                    help="allowlist file of accepted ta_hash values")
    ap.add_argument("--evidence", default="-",
                    help="file with the CA output or bare hex (default stdin)")
    args = ap.parse_args(argv)

    try:
        nonce = bytes.fromhex(args.nonce)
        if len(nonce) != NONCE_LEN:
            raise ValueError(f"nonce must be {2 * NONCE_LEN} hex chars")
        pub = load_pubkey(args.pubkey)
        tee_allow = load_allowlist(args.tee_allow)
        ta_allow = load_allowlist(args.ta_allow)
        if args.evidence == "-":
            text = sys.stdin.read()
        else:
            with open(args.evidence, encoding="utf-8") as f:
                text = f.read()
        blob = extract_evidence(text)
    except (OSError, ValueError) as e:
        print(f"input error: {e}", file=sys.stderr)
        return 2

    try:
        ev = verify(blob, nonce, pub, tee_allow, ta_allow)
    except VerifyError as e:
        print(f"REJECT {e}")
        return 1

    print("OK")
    print(f"key_sha256={key_fingerprint(pub)}")
    print(f"tee_hash={ev.tee_hash.hex()}")
    print(f"ta_hash={ev.ta_hash.hex()}")
    print(f"ta_uuid={uuid_mod.UUID(bytes=ev.ta_uuid)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
