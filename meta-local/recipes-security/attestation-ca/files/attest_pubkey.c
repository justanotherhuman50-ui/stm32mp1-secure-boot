/* SPDX-License-Identifier: BSD-2-Clause */
/* Fetch the attestation PTA public key (GET_PUBKEY, 0x0). stdout: e=, n=, alg=. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <tee_client_api.h>

#define PTA_UUID { 0x39800861, 0x182a, 0x4720, \
  { 0x9b, 0x67, 0x2b, 0xcd, 0x62, 0x2b, 0xc0, 0xb5 } }
#define CMD_GET_PUBKEY 0

static void hex(const char *tag, const uint8_t *b, size_t n)
{
    printf("%s=", tag);
    for (size_t i = 0; i < n; i++)
        printf("%02x", b[i]);
    printf("\n");
}

int main(void)
{
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = PTA_UUID;
    uint32_t origin = 0;
    uint8_t e[16], n[1024];
    struct timespec t0, t1;
    TEEC_Result res = TEEC_InitializeContext(NULL, &ctx);

    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "init context failed: 0x%x\n", res);
        return 1;
    }
    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC,
                           NULL, NULL, &origin);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "open PTA session failed: 0x%x origin %u\n",
                res, origin);
        return 1;
    }
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_VALUE_OUTPUT, TEEC_NONE);
    op.params[0].tmpref.buffer = e;
    op.params[0].tmpref.size = sizeof(e);
    op.params[1].tmpref.buffer = n;
    op.params[1].tmpref.size = sizeof(n);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    res = TEEC_InvokeCommand(&sess, CMD_GET_PUBKEY, &op, &origin);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    fprintf(stderr, "invoke took %ld ms\n",
            (long)((t1.tv_sec - t0.tv_sec) * 1000 +
                   (t1.tv_nsec - t0.tv_nsec) / 1000000));
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "GET_PUBKEY failed: 0x%x origin %u (e_sz %zu n_sz %zu)\n",
                res, origin, (size_t)op.params[0].tmpref.size,
                (size_t)op.params[1].tmpref.size);
        return 2;
    }
    if (op.params[0].tmpref.size > sizeof(e) ||
        op.params[1].tmpref.size > sizeof(n)) {
        fprintf(stderr, "reported size exceeds buffer\n");
        return 3;
    }
    hex("e", e, op.params[0].tmpref.size);
    hex("n", n, op.params[1].tmpref.size);
    printf("alg=0x%x\n", op.params[2].value.a);
    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
    return 0;
}
