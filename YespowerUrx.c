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
		uint32_t u32[6];
	} hash;
	uint32_t n = pdata[19] - 1;
	const uint32_t Htarg = ptarget[6];
	int i;

	for (i = 0; i < 19; i++)
		be32enc(&data.u32[i], pdata[i]);

	do {
		be32enc(&data.u32[19], ++n);

		if (yespower_tls(data.u8, 80, &params, &hash.yb))
			abort();

		if (le32dec(&hash.u32[6]) <= Htarg) {
			for (i = 0; i < 6; i++)
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
