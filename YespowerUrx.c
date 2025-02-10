/*
 * Copyright 2011 ArtForz, 2011-2014 pooler, 2018 The Resistance developers,
 * 2020 The Sugarchain Yumekawa developers
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is loosely based on a tiny portion of pooler's cpuminer scrypt.c.
 *
 * === Modified Version with Randomization and Parallel Hashing ===
 *
 * This experimental version adds:
 *
 *  1. A fast xorshift32 PRNG to randomize nonce values (seeded from pdata[19]).
 *  2. Batching: multiple randomized nonces are generated in a batch.
 *  3. Parallel evaluation: using OpenMP the batch is processed in parallel.
 *
 * All external interfaces remain unchanged so that no other miner files are affected.
 *
 * IMPORTANT: Claims of massive speedup (e.g. "1000% faster") are very ambitious.
 * Actual performance improvements on memory–hard algorithms like yespower typically require
 * low–level algorithmic changes, vectorization, or even hardware acceleration. Test carefully.
 */

#include "cpuminer-config.h"
#include "miner.h"
#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#ifdef _OPENMP
#include <omp.h>
#endif

/* A fast xorshift32 PRNG used to randomize nonce values.
   (Not cryptographically secure—but fast and sufficient for nonce mixing.) */
static inline uint32_t xorshift32(uint32_t *state) {
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

/* Define the number of nonce candidates to process in one batch */
#define BATCH_SIZE 8

int scanhash_urx_yespower(int thr_id, uint32_t *pdata,
	const uint32_t *ptarget,
	uint32_t max_nonce, unsigned long *hashes_done)
{
	// yespower parameters remain constant
	static const yespower_params_t params = {
		.version  = YESPOWER_1_0,
		.N        = 2048,
		.r        = 32,
		.pers     = (const uint8_t *)"UraniumX",
		.perslen  = 8
	};

	/* 
	 * Prepare the constant portion of the data.
	 * The header is 80 bytes (20 uint32_t words). The first 19 words are constant.
	 */
	union {
		uint8_t u8[80];
		uint32_t u32[20];
	} data_const;
	for (int i = 0; i < 19; i++)
		be32enc(&data_const.u32[i], pdata[i]);

	/* The nonce is stored in the 20th word (pdata[19]).
	 * Use its current value as the seed for the PRNG.
	 */
	uint32_t initial_nonce = pdata[19];
	uint32_t prng_state = initial_nonce;
	unsigned long local_hashes_done = 0;

	/* Variables to capture a candidate result from the parallel region */
	volatile int candidate_found = 0;
	volatile uint32_t candidate_nonce = 0;

	/* Determine the maximum number of nonce attempts allowed.
	 * (Note: When using random nonces, this is simply the number of trials.)
	 */
	uint32_t attempts_allowed = max_nonce - initial_nonce;

	/* Process nonce candidates in batches until a valid hash is found,
	   the allowed number of attempts is exhausted, or a restart is requested. */
	while (local_hashes_done < attempts_allowed &&
	       !work_restart[thr_id].restart &&
	       !candidate_found) {

		/* Generate a batch of randomized nonce candidates */
		int batch_count = BATCH_SIZE;
		if (attempts_allowed - local_hashes_done < BATCH_SIZE)
			batch_count = attempts_allowed - local_hashes_done;

		uint32_t nonces[BATCH_SIZE];  // we always allocate BATCH_SIZE, use only first batch_count entries
		for (int i = 0; i < batch_count; i++) {
			nonces[i] = xorshift32(&prng_state);
			local_hashes_done++;
		}

		/* Process the batch in parallel.
		   Each candidate uses the constant portion from data_const and sets its own nonce.
		   OpenMP is used to issue the hash commands concurrently. */
		#pragma omp parallel for shared(candidate_found, candidate_nonce) schedule(static)
		for (int i = 0; i < batch_count; i++) {
			/* If another thread already found a valid hash, skip processing. */
			if (candidate_found)
				continue;

			/* Create a candidate data block by copying the constant portion.
			   (Only the first 19 words are constant; the 20th word is replaced with the nonce.) */
			uint8_t candidate_data[80];
			memcpy(candidate_data, data_const.u8, 76);  // 19 words * 4 bytes = 76 bytes

			/* Set the candidate nonce into the data block */
			be32enc(&((uint32_t *)candidate_data)[19], nonces[i]);

			/* Compute the yespower hash for this candidate */
			yespower_binary_t candidate_hash;
			if (yespower_tls(candidate_data, 80, &params, &candidate_hash))
				abort();

			/* First check: compare a selected word of the hash (converted to little–endian)
			   against the target. (This is the same as in the original code.) */
			if (le32dec(((uint32_t *)&candidate_hash)[7]) <= ptarget[7]) {
				/* Convert the hash to little–endian for the full test. */
				uint32_t local_hash[7];
				for (int j = 0; j < 7; j++)
					local_hash[j] = le32dec(&((uint32_t *)&candidate_hash)[j]);

				if (fulltest(local_hash, ptarget)) {
					/* Record the candidate nonce (use a critical section to avoid races). */
					#pragma omp critical
					{
						if (!candidate_found) {
							candidate_found = 1;
							candidate_nonce = nonces[i];
						}
					}
					/* Optionally, if your OpenMP version supports cancellation, you can cancel the loop:
					 * #pragma omp cancel for
					 */
				}
			}
		} // end of parallel batch
	} // end of while loop

	*hashes_done = local_hashes_done;
	/* Update the global nonce state.
	   If a candidate was found, use its nonce; otherwise, store the latest PRNG state. */
	pdata[19] = candidate_found ? candidate_nonce : prng_state;
	return candidate_found;
}
