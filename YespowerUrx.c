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
 * Modified to use randomization for nonce selection.
 */

#include "cpuminer-config.h"
#include "miner.h"

#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

/*
 * scanhash_urx_yespower
 *
 * Modified to select the nonce randomly rather than sequentially.
 *
 * Parameters:
 *   thr_id      - thread id (used to index work_restart[] for restart requests)
 *   pdata       - pointer to an array of 32-bit words representing the block header;
 *                 pdata[19] holds the nonce field.
 *   ptarget     - pointer to an array containing the target (the 8th word, index 7, is used for a quick test)
 *   max_nonce   - maximum number of hash attempts (iterations) to perform
 *   hashes_done - pointer to a counter that will be updated with the number of hashes attempted
 *
 * Returns 1 if a valid hash (meeting the full target) is found, 0 otherwise.
 */
int scanhash_urx_yespower(int thr_id, uint32_t *pdata,
	const uint32_t *ptarget,
	uint32_t max_nonce, unsigned long *hashes_done)
{
	static const yespower_params_t params = {
		.version = YESPOWER_1_0,
		.N = 2048,
		.r = 32,
		.pers = (const uint8_t *)"UraniumX",
		.perslen = 8
	};
	/* The union 'data' holds the 80-byte input block.
	 * Although one member is declared as an 8-byte array, the union’s size is that of the largest member,
	 * which is u32[20] (20 * 4 = 80 bytes). */
	union {
		uint8_t u8[8];
		uint32_t u32[20];
	} data;
	union {
		yespower_binary_t yb;
		uint32_t u32[7];
	} hash;
	unsigned long iterations = 0;
	uint32_t nonce = 0;
	const uint32_t Htarg = ptarget[7];
	int i;

	/* Copy the first 19 words of the block header from pdata into data.
	 * These words remain constant during hashing (only the 20th word, the nonce, will change). */
	for (i = 0; i < 19; i++)
		be32enc(&data.u32[i], pdata[i]);

	/* Instead of incrementing the nonce sequentially, we now randomize it.
	 * We perform at most 'max_nonce' iterations (each counts as one hash attempt)
	 * and we also check for a work restart request. */
	while (iterations < max_nonce && !work_restart[thr_id].restart) {
		/* Generate a random nonce value. */
		nonce = (uint32_t)rand();

		/* Encode the random nonce into the 20th word of the block header. */
		be32enc(&data.u32[19], nonce);

		iterations++;

		/* Compute the Yespower hash using the provided parameters.
		 * The input is 80 bytes (the full block header) stored in data.u8. */
		if (yespower_tls(data.u8, 80, &params, &hash.yb))
			abort();

		/* Quick test: check if one 32-bit word of the hash (word at index 7) meets the target.
		 * The value is decoded from little-endian format. */
		if (le32dec(&hash.u32[7]) <= Htarg) {
			/* Decode all 7 32-bit words of the hash from little-endian format. */
			for (i = 0; i < 7; i++)
				hash.u32[i] = le32dec(&hash.u32[i]);
			/* Perform the full target test.
			 * Only if fulltest returns true do we consider the hash valid. */
			if (fulltest(hash.u32, ptarget)) {
				*hashes_done = iterations;
				pdata[19] = nonce;
				return 1;
			}
		}
	}

	*hashes_done = iterations;
	/* Store the last nonce tried back into the block header. */
	pdata[19] = nonce;
	return 0;
}
