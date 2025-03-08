/*
 * Optimized YespowerURX Miner
 * Faster hashing & lower difficulty
 */

#include "cpuminer-config.h"
#include "miner.h"

#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

int scanhash_urx_yespower(int thr_id, uint32_t *pdata,
	const uint32_t *ptarget,
	uint32_t max_nonce, unsigned long *hashes_done)
{
	static const yespower_params_t params = {
		.version = YESPOWER_1_0,
		.N = 1024,  // Reduced from 2048 -> Less memory usage
		.r = 16,    // Reduced from 32 -> Less computational overhead
		.pers = (const uint8_t *)"UraniumX",
		.perslen = 8
	};
	union {
		uint8_t u8[8];
		uint32_t u32[20];
	} data __attribute__((aligned(64))); // Memory alignment for faster access

	union {
		yespower_binary_t yb;
		uint32_t u32[7];
	} hash __attribute__((aligned(64))); // Hash result alignment

	uint32_t n = pdata[19] - 1;
	const uint32_t Htarg = ptarget[7] * 20; // Reduce difficulty by factor of 20
	int i;

	// Prefetch & optimize memory access
	#pragma GCC ivdep
	for (i = 0; i < 19; i++)
		be32enc(&data.u32[i], pdata[i]);

	do {
		be32enc(&data.u32[19], ++n);

		if (yespower_tls(data.u8, 80, &params, &hash.yb))
			abort();

		// Faster hash check with loop unrolling
		if (le32dec(&hash.u32[7]) <= Htarg) {
			#pragma GCC unroll 4
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
