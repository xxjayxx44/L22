/*
 * Copyright 2011 ArtForz, 2011-2014 pooler,
 * 2018 The Resistance developers, 2020 The Sugarchain Yumekawa developers
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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
 */

#include "cpuminer-config.h"
#include "miner.h"

#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>  /* For randomization */

/*
 * yespower_power2b_hash - Compute the power2b variant of the yespower hash.
 *
 * This function wraps yespower_tls() with parameters specific to power2b.
 *
 * Parameters:
 *   input    - Pointer to input data (e.g. block header).
 *   inputlen - Length of input data in bytes.
 *   output   - Pointer to a buffer where the hash will be stored.
 *
 * Returns:
 *   0 on success, nonzero if the underlying yespower_tls() call fails.
 */
int yespower_power2b_hash(const void *input, size_t inputlen, void *output)
{
    static const yespower_params_t power2b_params = {
        .version = YESPOWER_1_0,             /* Using version 1.0 (adjust if needed) */
        .N       = 2048,                     /* Memory cost factor */
        .r       = 32,                       /* Block-mixing parameter */
        .pers    = (const uint8_t *)"uraniumx",/* Personalization string for uraniumx*/
        .perslen = 8                         /* Length of "uraniumx" */
    };

    return yespower_tls(input, inputlen, &uraniumx_params, output);
}

/*
 * scanhash_urx_yespower - Modified to mine power2b with added randomization.
 *
 * This function searches for a valid nonce that produces a hash meeting the target
 * criteria using the power2b variant of the yespower algorithm.
 *
 * Parameters:
 *   thr_id      - Thread identifier.
 *   pdata       - Pointer to block header data (array of 32-bit words).
 *                 (pdata[19] is used to store the nonce.)
 *   ptarget     - Pointer to target hash (array of 32-bit words).
 *   max_nonce   - Maximum nonce value to try.
 *   hashes_done - Pointer to a counter for the number of hashes computed.
 *
 * Returns:
 *   1 if a valid nonce is found; 0 otherwise.
 */
int scanhash_urx_yespower(int thr_id, uint32_t *pdata,
    const uint32_t *ptarget,
    uint32_t max_nonce, unsigned long *hashes_done)
{
    /* This union allows access to the 80-byte block header as either 80 bytes or 20 uint32_t words. */
    union {
        uint8_t u8[8];     /* 80 bytes (20 * 4 bytes) */
        uint32_t u32[20];
    } data;
    /* This union is used to hold the resulting hash (7 32-bit words). */
    union {
        yespower_binary_t yb;
        uint32_t u32[7];
    } hash;
    uint32_t n;
    const uint32_t Htarg = ptarget[7];
    int i;

    /*
     * Randomize starting nonce if pdata[19] is 0.
     * Otherwise, continue scanning from the previously stored nonce.
     * 
     * Note: For proper randomization across threads, ensure that the RNG
     * is seeded (for example, by calling srand(time(NULL) ^ (thr_id << 16)))
     * during thread initialization.
     */
    if (pdata[19] == 0)
        n = (uint32_t)rand();
    else
        n = pdata[19] - 1;

    /* Encode the first 19 32-bit words of the block header into the data buffer in big-endian order */
    for (i = 0; i < 19; i++)
        be32enc(&data.u32[i], pdata[i]);

    do {
        /* Increment nonce and encode it in big-endian into the 20th word */
        be32enc(&data.u32[19], ++n);

        /* Compute the power2b hash using our dedicated wrapper function */
        if (yespower_power2b_hash(data.u8, 80, &hash.yb))
            abort();

        /* Check the preliminary target condition by comparing the 8th uint32_t of the hash
           (after conversion from little-endian) to the target value. */
        if (le32dec(&hash.u32[7]) <= Htarg) {
            for (i = 0; i < 7; i++)
                hash.u32[i] = le32dec(&hash.u32[i]);
            if (fulltest(hash.u32, ptarget)) {
                *hashes_done = n - pdata[19] + 1;
                pdata[19] = n;
                return 1;
            }
        }
    } while (n < max_nonce && !work_restart[thr_id].restart);

    *hashes_done = n - pdata[19] + 1;
    pdata[19] = n;
    return 0;
}
