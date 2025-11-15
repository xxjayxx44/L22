/*-
 * Copyright 2005-2016 Colin Percival
 * All rights reserved.
 *
 * ULTRA-OPTIMIZED SHA256 HEADER FOR MAXIMUM MINING PERFORMANCE
 */

#ifndef _SHA256_H_
#define _SHA256_H_

#include <stddef.h>
#include <stdint.h>

/* COMPILER OPTIMIZATIONS */
#ifdef __GNUC__
#define ALWAYS_INLINE __attribute__((always_inline))
#define HOT __attribute__((hot))
#define COLD __attribute__((cold))
#else
#define ALWAYS_INLINE
#define HOT
#define COLD
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Use #defines in order to avoid namespace collisions with anyone else's
 * SHA256 code (e.g., the code in OpenSSL).
 */
#define SHA256_Init libcperciva_SHA256_Init
#define SHA256_Update libcperciva_SHA256_Update
#define SHA256_Final libcperciva_SHA256_Final
#define SHA256_Buf libcperciva_SHA256_Buf
#define SHA256_CTX libcperciva_SHA256_CTX
#define HMAC_SHA256_Init libcperciva_HMAC_SHA256_Init
#define HMAC_SHA256_Update libcperciva_HMAC_SHA256_Update
#define HMAC_SHA256_Final libcperciva_HMAC_SHA256_Final
#define HMAC_SHA256_Buf libcperciva_HMAC_SHA256_Buf
#define HMAC_SHA256_CTX libcperciva_HMAC_SHA256_CTX
#define PBKDF2_SHA256 libcperciva_PBKDF2_SHA256

/* Context structure for SHA256 operations. */
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buf[64];
} SHA256_CTX;

/* Context structure for HMAC-SHA256 operations. */
typedef struct {
    SHA256_CTX ictx;
    SHA256_CTX octx;
} HMAC_SHA256_CTX;

/* ULTRA-FAST SHA256 OPERATIONS - OPTIMIZED FOR MINING */

/**
 * SHA256_Init(ctx):
 * Initialize the SHA256 context ${ctx}.
 * ULTRA-OPTIMIZED: Direct state assignment, no memcpy
 */
ALWAYS_INLINE HOT void SHA256_Init(SHA256_CTX *);

/**
 * SHA256_Update(ctx, in, len):
 * Input ${len} bytes from ${in} into the SHA256 context ${ctx}.
 * ULTRA-OPTIMIZED: Fast path for full blocks, minimal branching
 */
ALWAYS_INLINE HOT void SHA256_Update(SHA256_CTX *, const void *, size_t);

/**
 * SHA256_Final(digest, ctx):
 * Output the SHA256 hash of the data input to the context ${ctx} into the
 * buffer ${digest}.
 * ULTRA-OPTIMIZED: Unrolled output, direct encoding
 */
ALWAYS_INLINE HOT void SHA256_Final(uint8_t[32], SHA256_CTX *);

/**
 * SHA256_Buf(in, len, digest):
 * Compute the SHA256 hash of ${len} bytes from ${in} and write it to ${digest}.
 * ULTRA-OPTIMIZED: Single-shot optimized for mining patterns
 */
ALWAYS_INLINE HOT void SHA256_Buf(const void *, size_t, uint8_t[32]);

/**
 * HMAC_SHA256_Init(ctx, K, Klen):
 * Initialize the HMAC-SHA256 context ${ctx} with ${Klen} bytes of key from
 * ${K}.
 * ULTRA-OPTIMIZED: Fast key processing, optimized for mining key sizes
 */
ALWAYS_INLINE HOT void HMAC_SHA256_Init(HMAC_SHA256_CTX *, const void *, size_t);

/**
 * HMAC_SHA256_Update(ctx, in, len):
 * Input ${len} bytes from ${in} into the HMAC-SHA256 context ${ctx}.
 * ULTRA-OPTIMIZED: Direct passthrough to SHA256_Update
 */
ALWAYS_INLINE HOT void HMAC_SHA256_Update(HMAC_SHA256_CTX *, const void *, size_t);

/**
 * HMAC_SHA256_Final(digest, ctx):
 * Output the HMAC-SHA256 of the data input to the context ${ctx} into the
 * buffer ${digest}.
 * ULTRA-OPTIMIZED: Minimal intermediate hashing
 */
ALWAYS_INLINE HOT void HMAC_SHA256_Final(uint8_t[32], HMAC_SHA256_CTX *);

/**
 * HMAC_SHA256_Buf(K, Klen, in, len, digest):
 * Compute the HMAC-SHA256 of ${len} bytes from ${in} using the key ${K} of
 * length ${Klen}, and write the result to ${digest}.
 * ULTRA-OPTIMIZED: Complete operation with maximum inlining
 */
ALWAYS_INLINE HOT void HMAC_SHA256_Buf(const void *, size_t, const void *, size_t, uint8_t[32]);

/**
 * PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA256 as the PRF, and
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
 * ULTRA-OPTIMIZED: Optimized for typical mining parameters (c=1)
 */
ALWAYS_INLINE HOT void PBKDF2_SHA256(const uint8_t *, size_t, const uint8_t *, size_t,
    uint64_t, uint8_t *, size_t);

/* MINING-SPECIFIC OPTIMIZED FUNCTIONS */

/**
 * SHA256_Transform(state, block):
 * Core SHA256 transform function. Process one 64-byte block.
 * ULTRA-OPTIMIZED: Fully unrolled for maximum performance
 */
ALWAYS_INLINE HOT void SHA256_Transform(uint32_t state[8], const uint8_t block[64]);

/**
 * SHA256_Single(data, len, digest):
 * Single-block optimized SHA256 for small inputs (<= 64 bytes)
 * ULTRA-OPTIMIZED: Specialized for common mining input sizes
 */
ALWAYS_INLINE HOT void SHA256_Single(const void *data, size_t len, uint8_t digest[32]);

/**
 * HMAC_SHA256_Fast(key, keylen, data, datalen, digest):
 * Fast HMAC for fixed-size keys common in mining
 * ULTRA-OPTIMIZED: Assumes 32-byte keys for mining optimization
 */
ALWAYS_INLINE HOT void HMAC_SHA256_Fast(const uint8_t key[32], const void *data, 
                                       size_t datalen, uint8_t digest[32]);

/**
 * PBKDF2_SHA256_Mining(passwd, salt, buf):
 * Mining-optimized PBKDF2 with fixed parameters (c=1, dkLen=32)
 * ULTRA-OPTIMIZED: Hardcoded for yespower mining parameters
 */
ALWAYS_INLINE HOT void PBKDF2_SHA256_Mining(const uint8_t passwd[32], 
                                           const uint8_t salt[80], 
                                           uint8_t buf[32]);

/* PERFORMANCE MONITORING (DEBUG BUILD ONLY) */
#ifdef SHA256_PERF_STATS
/**
 * SHA256_GetStats():
 * Get performance statistics for optimization tuning
 */
void SHA256_GetStats(uint64_t *transforms, uint64_t *bytes_processed);
#endif

/* MEMORY OPTIMIZATIONS */

/**
 * SHA256_CTX_AlignedAlloc():
 * Allocate cache-aligned SHA256 context for optimal performance
 */
SHA256_CTX *SHA256_CTX_AlignedAlloc(void);

/**
 * SHA256_CTX_AlignedFree(ctx):
 * Free aligned SHA256 context
 */
void SHA256_CTX_AlignedFree(SHA256_CTX *ctx);

/* BATCH PROCESSING FOR MINING */

/**
 * SHA256_Batch4(inputs, lengths, digests, count):
 * Process multiple SHA256 hashes in batch (up to 4)
 * ULTRA-OPTIMIZED: Vector-friendly processing for multiple nonces
 */
ALWAYS_INLINE HOT void SHA256_Batch4(const void *inputs[4], const size_t lengths[4],
                                    uint8_t digests[4][32], int count);

/**
 * HMAC_SHA256_Batch4(keys, keylens, datas, datalens, digests, count):
 * Process multiple HMAC-SHA256 in batch (up to 4)
 * ULTRA-OPTIMIZED: Parallel processing for mining workloads
 */
ALWAYS_INLINE HOT void HMAC_SHA256_Batch4(const void *keys[4], const size_t keylens[4],
                                         const void *datas[4], const size_t datalens[4],
                                         uint8_t digests[4][32], int count);

#ifdef __cplusplus
}
#endif

#endif /* !_SHA256_H_ */
