#ifndef SHA256_PARALLEL_H
#define SHA256_PARALLEL_H

#include <stdint.h>

// Two-way interleaved SHA-256 core.
// Compress blockA into stateA and blockB into stateB in one go.
void sha256_compress2(uint32_t stateA[8],
                      const uint32_t blockA[16],
                      uint32_t stateB[8],
                      const uint32_t blockB[16]);

#endif
