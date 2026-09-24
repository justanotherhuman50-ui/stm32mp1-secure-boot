/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

/* Provides ATTESTATION_TA_UUID */
#include <attestation_ta.h>

#define TA_UUID			ATTESTATION_TA_UUID

/*
 * Stateless per request, so no SINGLE_INSTANCE/KEEP_ALIVE: every call is
 * measured from a fresh instance (HASH_TA_MEMORY measures read-only
 * segments only, so instance state does not change the hash).
 */
#define TA_FLAGS		TA_FLAG_EXEC_DDR

/*
 * Stack: 506-byte evidence buffer, 32-byte nonce', hash temporaries, and
 * the TEE_InvokeTACommand marshalling. 4 KiB is comfortable.
 * Data (heap): TEE_AllocateOperation handles only. 16 KiB, to be trimmed
 * after measuring the heap high-water mark on the board.
 */
#define TA_STACK_SIZE		(4 * 1024)
#define TA_DATA_SIZE		(16 * 1024)

#define TA_VERSION		"1.0"
#define TA_DESCRIPTION		"Capstone remote attestation TA (evidence v1)"

#endif /* USER_TA_HEADER_DEFINES_H */
