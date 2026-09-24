/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Capstone attestation TA: interface shared by the TA and its client.
 * Evidence format v1, see engineering log 2026-09-24 (later 8).
 */
#ifndef ATTESTATION_TA_H
#define ATTESTATION_TA_H

/* 6e6c47cd-0a2e-4e8a-b15b-b08469dbae06 */
#define ATTESTATION_TA_UUID \
	{ 0x6e6c47cd, 0x0a2e, 0x4e8a, \
		{ 0xb1, 0x5b, 0xb0, 0x84, 0x69, 0xdb, 0xae, 0x06 } }

/*
 * CMD_GET_EVIDENCE
 * param[0] memref input : verifier nonce, exactly ATT_NONCE_LEN bytes
 * param[1] memref output: evidence blob (see layout below)
 * param[2], param[3]    : unused (TEE_PARAM_TYPE_NONE)
 * On a short output buffer the TA returns TEE_ERROR_SHORT_BUFFER and sets
 * param[1].memref.size to the required size.
 */
#define ATTESTATION_CMD_GET_EVIDENCE	0

#define ATT_MAGIC		"RAT1"
#define ATT_VERSION		1

#define ATT_NONCE_LEN		32
#define ATT_HASH_LEN		32
#define ATT_UUID_LEN		16

/* Claims, big-endian, fixed size, no padding */
#define ATT_OFF_MAGIC		0
#define ATT_OFF_VERSION		4
#define ATT_OFF_RESERVED	6
#define ATT_OFF_NONCE		8
#define ATT_OFF_TEE_HASH	40
#define ATT_OFF_TA_UUID		72
#define ATT_CLAIMS_LEN		88

/* Trailer: ta_hash(32) | sig_len(2, BE) | sig(sig_len) */
#define ATT_OFF_TA_HASH		ATT_CLAIMS_LEN
#define ATT_OFF_SIG_LEN		(ATT_OFF_TA_HASH + ATT_HASH_LEN)
#define ATT_OFF_SIG		(ATT_OFF_SIG_LEN + 2)

#endif /* ATTESTATION_TA_H */
