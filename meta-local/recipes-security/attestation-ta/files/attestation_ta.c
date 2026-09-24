// SPDX-License-Identifier: BSD-2-Clause
/*
 * Capstone remote attestation TA. Evidence format v1 (see attestation_ta.h).
 *
 * Flow per CMD_GET_EVIDENCE:
 *  1. Copy the verifier nonce out of shared memory (single read).
 *  2. PTA 0x3 (HASH_TEE_MEMORY) -> tee_hash. Its signature is discarded.
 *  3. Build the 88-byte claims in TA-private memory.
 *  4. nonce' = SHA256(nonce || SHA256(claims)).
 *  5. PTA 0x2 (HASH_TA_MEMORY, caller = this TA) with nonce' -> ta_hash | sig,
 *     where sig = PSS-SHA256(SHA256(nonce' || ta_hash)), salt 32.
 *  6. Assemble claims | ta_hash | sig_len | sig into the caller's buffer.
 */
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <pta_attestation.h>
#include <attestation_ta.h>

/* Largest RSA modulus the PTA can be configured with here: 4096 bits */
#define ATT_MAX_SIG_LEN		512
#define ATT_SCRATCH_LEN		(ATT_HASH_LEN + ATT_MAX_SIG_LEN)
/* Default PTA key is RSA-3072 (384-byte signature): 506 bytes of evidence */
#define ATT_MIN_OUT_LEN		(ATT_CLAIMS_LEN + ATT_HASH_LEN + 2 + 384)

static const TEE_UUID pta_uuid = PTA_ATTESTATION_UUID;
static const TEE_UUID self_uuid = ATTESTATION_TA_UUID;

static void put_be16(uint8_t *p, uint16_t v)
{
	p[0] = v >> 8;
	p[1] = v;
}

static void put_be32(uint8_t *p, uint32_t v)
{
	put_be16(p, v >> 16);
	put_be16(p + 2, v);
}

/* RFC 4122 byte order, same as Python uuid.UUID(...).bytes */
static void put_uuid(uint8_t *p, const TEE_UUID *u)
{
	put_be32(p, u->timeLow);
	put_be16(p + 4, u->timeMid);
	put_be16(p + 6, u->timeHiAndVersion);
	memcpy(p + 8, u->clockSeqAndNode, sizeof(u->clockSeqAndNode));
}

/*
 * Invoke one attestation PTA command. On success *out_len is the size the
 * PTA reports (hash + modulus size). The PTA runs init_key() before it checks
 * the output size, so even a failing call can trigger first-use key
 * generation.
 */
static TEE_Result call_pta(TEE_TASessionHandle sess, uint32_t cmd,
			   void *nonce, size_t nonce_len,
			   uint8_t *out, size_t *out_len)
{
	const uint32_t pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					    TEE_PARAM_TYPE_MEMREF_OUTPUT,
					    TEE_PARAM_TYPE_NONE,
					    TEE_PARAM_TYPE_NONE);
	TEE_Param p[TEE_NUM_PARAMS] = { };
	uint32_t eo = 0;
	TEE_Result res = TEE_SUCCESS;

	p[0].memref.buffer = nonce;
	p[0].memref.size = nonce_len;
	p[1].memref.buffer = out;
	p[1].memref.size = *out_len;

	res = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE, cmd, pt, p, &eo);
	if (res) {
		EMSG("PTA cmd %u failed: %#x (origin %u)", cmd, res, eo);
		return res;
	}
	*out_len = p[1].memref.size;
	if (*out_len < ATT_HASH_LEN || *out_len > ATT_SCRATCH_LEN)
		return TEE_ERROR_GENERIC;
	return TEE_SUCCESS;
}

static TEE_Result get_evidence(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	/* All of these are TA-private: shared memory is copied once */
	uint8_t nonce[ATT_NONCE_LEN] = { };
	uint8_t claims[ATT_CLAIMS_LEN] = { };
	uint8_t scratch[ATT_SCRATCH_LEN] = { };
	uint8_t tee_hash[ATT_HASH_LEN] = { };
	uint8_t claims_hash[ATT_HASH_LEN] = { };
	uint8_t nonce_bound[ATT_HASH_LEN] = { };
	uint8_t *out = params[1].memref.buffer;
	TEE_TASessionHandle sess = TEE_HANDLE_NULL;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_Result res = TEE_SUCCESS;
	size_t scratch_len = 0;
	size_t sig_len = 0;
	size_t total = 0;
	size_t l = 0;
	uint32_t eo = 0;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!params[0].memref.buffer ||
	    params[0].memref.size != ATT_NONCE_LEN)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!out && params[1].memref.size)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Reject early: avoids two RSA private ops for a too-small buffer */
	if (params[1].memref.size < ATT_MIN_OUT_LEN) {
		params[1].memref.size = ATT_MIN_OUT_LEN;
		return TEE_ERROR_SHORT_BUFFER;
	}

	memcpy(nonce, params[0].memref.buffer, ATT_NONCE_LEN);

	res = TEE_OpenTASession(&pta_uuid, TEE_TIMEOUT_INFINITE, 0, NULL,
				&sess, &eo);
	if (res) {
		EMSG("open attestation PTA: %#x (origin %u)", res, eo);
		return res;
	}

	/* 2. TEE OS measurement; the PTA signature is not used */
	scratch_len = sizeof(scratch);
	res = call_pta(sess, PTA_ATTESTATION_HASH_TEE_MEMORY, nonce,
		       sizeof(nonce), scratch, &scratch_len);
	if (res)
		goto out;
	memcpy(tee_hash, scratch, ATT_HASH_LEN);

	/* 3. Claims */
	memcpy(claims + ATT_OFF_MAGIC, ATT_MAGIC, 4);
	put_be16(claims + ATT_OFF_VERSION, ATT_VERSION);
	put_be16(claims + ATT_OFF_RESERVED, 0);
	memcpy(claims + ATT_OFF_NONCE, nonce, ATT_NONCE_LEN);
	memcpy(claims + ATT_OFF_TEE_HASH, tee_hash, ATT_HASH_LEN);
	put_uuid(claims + ATT_OFF_TA_UUID, &self_uuid);

	/* 4. nonce' = SHA256(nonce || SHA256(claims)); DoFinal resets op */
	res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
	if (res)
		goto out;
	l = sizeof(claims_hash);
	res = TEE_DigestDoFinal(op, claims, sizeof(claims), claims_hash, &l);
	if (res)
		goto out;
	TEE_DigestUpdate(op, nonce, sizeof(nonce));
	l = sizeof(nonce_bound);
	res = TEE_DigestDoFinal(op, claims_hash, sizeof(claims_hash),
				nonce_bound, &l);
	if (res)
		goto out;

	/* 5. TA measurement + signature, PTA measures this TA (the caller) */
	scratch_len = sizeof(scratch);
	res = call_pta(sess, PTA_ATTESTATION_HASH_TA_MEMORY, nonce_bound,
		       sizeof(nonce_bound), scratch, &scratch_len);
	if (res)
		goto out;
	sig_len = scratch_len - ATT_HASH_LEN;

	/* 6. Assemble */
	total = ATT_OFF_SIG + sig_len;
	if (params[1].memref.size < total) {
		params[1].memref.size = total;
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}
	memcpy(out, claims, ATT_CLAIMS_LEN);
	memcpy(out + ATT_OFF_TA_HASH, scratch, ATT_HASH_LEN);
	put_be16(out + ATT_OFF_SIG_LEN, sig_len);
	memcpy(out + ATT_OFF_SIG, scratch + ATT_HASH_LEN, sig_len);
	params[1].memref.size = total;
out:
	if (op != TEE_HANDLE_NULL)
		TEE_FreeOperation(op);
	TEE_CloseTASession(sess);
	return res;
}

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t pt, TEE_Param params[4],
				    void **sess)
{
	(void)pt;
	(void)params;
	(void)sess;
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess)
{
	(void)sess;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess, uint32_t cmd, uint32_t pt,
				      TEE_Param params[4])
{
	(void)sess;

	switch (cmd) {
	case ATTESTATION_CMD_GET_EVIDENCE:
		return get_evidence(pt, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
