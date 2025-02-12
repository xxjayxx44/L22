#include "cpuminer-config.h"
#include "miner.h"
#include "yespower-1.0.1/yespower.h"
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <omp.h> // Include OpenMP header

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
	union {
		uint8_t u8[8];
		uint32_t u32[20];
	} data;
	union {
		yespower_binary_t yb;
		uint32_t u32[7];
	} hash;
	uint32_t n = pdata[19] - 1;
	const uint32_t Htarg = ptarget[7];
	int i;

	for (i = 0; i < 19; i++)
		be32enc(&data.u32[i], pdata[i]);

	// Flag to indicate if a valid hash is found
	int found = 0;

	// Parallelize the loop using OpenMP
	#pragma omp parallel for shared(found) schedule(dynamic)
	for (uint32_t nonce = n + 1; nonce <= max_nonce; nonce++) {
		if (found) continue; // Early exit if another thread found a valid hash

		union {
			uint8_t u8[8];
			uint32_t u32[20];
		} local_data;
		memcpy(local_data.u32, data.u32, sizeof(data.u32));
		be32enc(&local_data.u32[19], nonce);

		if (yespower_tls(local_data.u8, 80, &params, &hash.yb))
			abort();

		if (le32dec(&hash.u32[7]) <= Htarg) {
			for (i = 0; i < 7; i++)
				hash.u32[i] = le32dec(&hash.u32[i]);
			if (fulltest(hash.u32, ptarget)) {
				#pragma omp critical
				{
					if (!found) { // Ensure only one thread updates the result
						found = 1;
						*hashes_done = nonce - pdata[19] + 1;
						pdata[19] = nonce;
					}
				}
			}
		}
	}

	return found;
}
