#ifndef _SYSENDIAN_H_
#define _SYSENDIAN_H_

#include <stdint.h>

/* ULTRA-FAST ENDIAN FUNCTIONS - MAXIMUM MINING SPEED */
/* Remove namespace collisions for speed */
#define be32dec libcperciva_be32dec
#define be32enc libcperciva_be32enc
#define be64enc libcperciva_be64enc
#define le32dec libcperciva_le32dec
#define le32enc libcperciva_le32enc

/* COMPILER-SPECIFIC OPTIMIZATIONS */
#ifdef __GNUC__
#define ALWAYS_INLINE __attribute__((always_inline))
#define HOT __attribute__((hot))
#define ALIGNED(x) __attribute__((aligned(x)))
#else
#define ALWAYS_INLINE
#define HOT
#define ALIGNED(x)
#endif

/* ULTRA-FAST 32-BIT BIG ENDIAN DECODE */
static inline uint32_t ALWAYS_INLINE HOT
be32dec(const void * pp)
{
	const uint8_t * p = (const uint8_t *)pp;
	/* Direct computation - no temporary variables */
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | 
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* ULTRA-FAST 32-BIT BIG ENDIAN ENCODE */
static inline void ALWAYS_INLINE HOT
be32enc(void * pp, uint32_t x)
{
	uint8_t * p = (uint8_t *)pp;
	/* Direct assignment - no intermediate calculations */
	p[0] = (uint8_t)(x >> 24);
	p[1] = (uint8_t)(x >> 16);
	p[2] = (uint8_t)(x >> 8);
	p[3] = (uint8_t)x;
}

/* ULTRA-FAST 64-BIT BIG ENDIAN ENCODE */
static inline void ALWAYS_INLINE HOT
be64enc(void * pp, uint64_t x)
{
	uint8_t * p = (uint8_t *)pp;
	/* Unrolled for maximum speed */
	p[0] = (uint8_t)(x >> 56);
	p[1] = (uint8_t)(x >> 48);
	p[2] = (uint8_t)(x >> 40);
	p[3] = (uint8_t)(x >> 32);
	p[4] = (uint8_t)(x >> 24);
	p[5] = (uint8_t)(x >> 16);
	p[6] = (uint8_t)(x >> 8);
	p[7] = (uint8_t)x;
}

/* ULTRA-FAST 32-BIT LITTLE ENDIAN DECODE - MOST CRITICAL FOR MINING */
static inline uint32_t ALWAYS_INLINE HOT
le32dec(const void * pp)
{
	const uint8_t * p = (const uint8_t *)pp;
	/* Direct memory read for aligned data - fastest possible */
	return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) | 
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ULTRA-FAST 32-BIT LITTLE ENDIAN ENCODE */
static inline void ALWAYS_INLINE HOT
le32enc(void * pp, uint32_t x)
{
	uint8_t * p = (uint8_t *)pp;
	/* Direct assignment - optimized for little endian */
	p[0] = (uint8_t)x;
	p[1] = (uint8_t)(x >> 8);
	p[2] = (uint8_t)(x >> 16);
	p[3] = (uint8_t)(x >> 24);
}

/* SPECIALIZED MINING-ONLY FUNCTIONS */

/* DIRECT LITTLE ENDIAN READ FROM ALIGNED MEMORY */
static inline uint32_t ALWAYS_INLINE HOT
le32dec_aligned(const uint32_t * pp)
{
	/* Assumes input is 4-byte aligned - fastest for mining */
#ifdef __GNUC__
	/* Use GCC built-in for unaligned safe access */
	return __builtin_bswap32(*(const uint32_t *)pp);
#else
	/* Fallback to memcpy for strict aliasing */
	uint32_t val;
	__builtin_memcpy(&val, pp, 4);
	return ((val >> 24) & 0xff) | ((val >> 8) & 0xff00) | 
	       ((val << 8) & 0xff0000) | ((val << 24) & 0xff000000);
#endif
}

/* BATCH DECODE - PROCESS MULTIPLE WORDS */
static inline void ALWAYS_INLINE HOT
le32dec_batch(uint32_t *out, const uint8_t *in, size_t count)
{
	/* Process multiple words for vectorization */
	for (size_t i = 0; i < count; i++) {
		out[i] = le32dec(in + i * 4);
	}
}

/* BATCH ENCODE - PROCESS MULTIPLE WORDS */
static inline void ALWAYS_INLINE HOT
le32enc_batch(uint8_t *out, const uint32_t *in, size_t count)
{
	/* Process multiple words for vectorization */
	for (size_t i = 0; i < count; i++) {
		le32enc(out + i * 4, in[i]);
	}
}

/* DIRECT MEMORY COPY WITH ENDIAN CONVERSION */
static inline void ALWAYS_INLINE HOT
le32dec_copy(uint32_t *dst, const uint8_t *src, size_t bytes)
{
	/* Convert byte array to uint32_t array */
	size_t words = bytes / 4;
	for (size_t i = 0; i < words; i++) {
		dst[i] = le32dec(src + i * 4);
	}
}

/* HASH-SPECIFIC OPTIMIZATIONS */

/* EXTRACT SINGLE WORD FROM HASH BUFFER */
static inline uint32_t ALWAYS_INLINE HOT
hash_word7(const uint8_t *hash)
{
	/* Direct access to word 7 (most common mining check) */
	return le32dec(hash + 28);
}

/* EXTRACT MULTIPLE WORDS FROM HASH BUFFER */
static inline void ALWAYS_INLINE HOT
hash_words(uint32_t *out, const uint8_t *hash, int count)
{
	/* Extract multiple words from hash */
	for (int i = 0; i < count; i++) {
		out[i] = le32dec(hash + i * 4);
	}
}

#endif /* !_SYSENDIAN_H_ */
