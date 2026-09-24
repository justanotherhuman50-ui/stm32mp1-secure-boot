/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Test client for the capstone attestation TA (evidence v1).
 *
 * Usage: attest_ca [nonce_hex]
 *   nonce_hex: 64 hex chars (32 bytes). Without it a random nonce is drawn
 *   from getrandom().
 *
 * stdout: "nonce=<hex>" and "evidence=<hex>" (verifier input).
 * stderr: diagnostics and the invoke latency.
 * Exit: 0 ok, 1 usage/setup, 2 TEE call failed, 3 evidence framing invalid.
 *
 * The first call after a key wipe triggers RSA key generation in the
 * attestation PTA. libteec has no invoke timeout, so the call simply blocks.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/types.h>
#include <time.h>
#include <tee_client_api.h>

#include "attestation_ta.h"

#define OUT_BUF_LEN		1024
#define MAX_EVIDENCE_LEN	(64 * 1024)

static void print_hex(const char *label, const uint8_t *p, size_t n)
{
	size_t i;

	printf("%s=", label);
	for (i = 0; i < n; i++)
		printf("%02x", p[i]);
	printf("\n");
}

static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static int parse_hex(const char *s, uint8_t *out, size_t n)
{
	size_t i;

	if (strlen(s) != 2 * n)
		return -1;
	for (i = 0; i < n; i++) {
		int hi = hexval(s[2 * i]);
		int lo = hexval(s[2 * i + 1]);

		if (hi < 0 || lo < 0)
			return -1;
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return 0;
}

static int random_nonce(uint8_t *n, size_t len)
{
	size_t got = 0;

	while (got < len) {
		ssize_t r = getrandom(n + got, len - got, 0);

		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		got += (size_t)r;
	}
	return 0;
}

/*
 * One invoke, plus one retry if the TA reports a larger required size
 * (a bigger key than RSA-3072). On success *out_p owns the buffer.
 */
static TEEC_Result get_evidence(TEEC_Session *sess, const uint8_t *nonce,
				uint8_t **out_p, size_t *out_len,
				uint32_t *origin)
{
	TEEC_Operation op;
	TEEC_Result res = TEEC_ERROR_OUT_OF_MEMORY;
	size_t cap = OUT_BUF_LEN;
	uint8_t *out = malloc(cap);
	int attempt;

	if (!out)
		return res;

	for (attempt = 0; attempt < 2; attempt++) {
		size_t need;
		uint8_t *tmp;

		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = (void *)nonce;
		op.params[0].tmpref.size = ATT_NONCE_LEN;
		op.params[1].tmpref.buffer = out;
		op.params[1].tmpref.size = cap;

		res = TEEC_InvokeCommand(sess, ATTESTATION_CMD_GET_EVIDENCE,
					 &op, origin);
		if (res != TEEC_ERROR_SHORT_BUFFER)
			break;

		need = op.params[1].tmpref.size;
		if (need <= cap || need > MAX_EVIDENCE_LEN)
			break;
		tmp = realloc(out, need);
		if (!tmp) {
			res = TEEC_ERROR_OUT_OF_MEMORY;
			break;
		}
		out = tmp;
		cap = need;
	}

	if (res == TEEC_SUCCESS) {
		*out_p = out;
		*out_len = op.params[1].tmpref.size;
	} else {
		free(out);
	}
	return res;
}

static void explain(const char *what, TEEC_Result res, uint32_t origin)
{
	fprintf(stderr, "%s failed: res=0x%08x origin=0x%x\n", what,
		(unsigned int)res, (unsigned int)origin);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND)
		fprintf(stderr, "  TA not found or tee-supplicant not running "
			"(TA is loaded from /lib/optee_armtz via the supplicant)\n");
	else if (res == TEEC_ERROR_OUT_OF_MEMORY)
		fprintf(stderr, "  out of memory in the TEE: core heap or TA heap "
			"(RSA-3072 keygen is the suspect on first use)\n");
	else if (res == TEEC_ERROR_TARGET_DEAD)
		fprintf(stderr, "  TA panicked; check the secure-world UART log\n");
	else if (res == TEEC_ERROR_COMMUNICATION)
		fprintf(stderr, "  communication with the TEE failed\n");
}

int main(int argc, char **argv)
{
	uint8_t nonce[ATT_NONCE_LEN];
	TEEC_UUID uuid = ATTESTATION_TA_UUID;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Result res;
	uint32_t origin = 0;
	uint8_t *ev = NULL;
	size_t ev_len = 0;
	struct timespec t0, t1;
	long ms;
	int rc = 1;

	if (argc > 2) {
		fprintf(stderr, "usage: %s [nonce_hex(64 chars)]\n", argv[0]);
		return 1;
	}
	if (argc == 2) {
		if (parse_hex(argv[1], nonce, sizeof(nonce))) {
			fprintf(stderr, "nonce must be exactly %d hex chars\n",
				2 * ATT_NONCE_LEN);
			return 1;
		}
	} else if (random_nonce(nonce, sizeof(nonce))) {
		perror("getrandom");
		return 1;
	}

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		explain("TEEC_InitializeContext (no TEE device?)", res, 0);
		return 1;
	}
	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
			       NULL, &origin);
	if (res != TEEC_SUCCESS) {
		explain("TEEC_OpenSession", res, origin);
		goto out_ctx;
	}

	clock_gettime(CLOCK_MONOTONIC, &t0);
	res = get_evidence(&sess, nonce, &ev, &ev_len, &origin);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	ms = (long)((t1.tv_sec - t0.tv_sec) * 1000 +
		    (t1.tv_nsec - t0.tv_nsec) / 1000000);
	fprintf(stderr, "invoke took %ld ms\n", ms);

	if (res != TEEC_SUCCESS) {
		explain("GET_EVIDENCE", res, origin);
		rc = 2;
		goto out_sess;
	}

	print_hex("nonce", nonce, sizeof(nonce));
	print_hex("evidence", ev, ev_len);

	/* Framing sanity only; all real validation is in the verifier. */
	rc = 0;
	if (ev_len < ATT_OFF_SIG) {
		fprintf(stderr, "evidence too short: %zu bytes\n", ev_len);
		rc = 3;
	} else {
		size_t sig_len = ((size_t)ev[ATT_OFF_SIG_LEN] << 8) |
				 ev[ATT_OFF_SIG_LEN + 1];

		if (ATT_OFF_SIG + sig_len != ev_len) {
			fprintf(stderr, "framing mismatch: sig_len=%zu, "
				"total=%zu\n", sig_len, ev_len);
			rc = 3;
		} else {
			fprintf(stderr, "evidence %zu bytes, sig_len %zu\n",
				ev_len, sig_len);
		}
	}

	free(ev);
out_sess:
	TEEC_CloseSession(&sess);
out_ctx:
	TEEC_FinalizeContext(&ctx);
	return rc;
}
