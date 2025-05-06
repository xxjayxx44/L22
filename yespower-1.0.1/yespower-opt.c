/*-
 * Copyright 2009 Colin Percival
 * Copyright 2012-2019 Alexander Peslyak
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
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 *
 * This is a proof-of-work focused fork of yescrypt, including optimized and
 * cut-down implementation of the obsolete yescrypt 0.5 (based off its first
 * submission to PHC back in 2014) and a new proof-of-work specific variation
 * known as yespower 1.0.  The former is intended as an upgrade for
 * cryptocurrencies that already use yescrypt 0.5 and the latter may be used
 * as a further upgrade (hard fork) by those and other cryptocurrencies.  The
 * version of algorithm to use is requested through parameters, allowing for
 * both algorithms to co-exist in client and miner implementations (such as in
 * preparation for a hard-fork).
 */

#ifndef _YESPOWER_OPT_C_PASS_
#define _YESPOWER_OPT_C_PASS_ 1
#endif

#if _YESPOWER_OPT_C_PASS_ == 1
/*
 * AVX and especially XOP speed up Salsa20 a lot, but needlessly result in
 * extra instruction prefixes for pwxform (which we make more use of).  While
 * no slowdown from the prefixes is generally observed on AMD CPUs supporting
 * XOP, some slowdown is sometimes observed on Intel CPUs with AVX.
 */
#ifdef __XOP__
#warning "Note: XOP is enabled.  That's great."
#elif defined(__AVX__)
#warning "Note: AVX is enabled.  That's OK."
#elif defined(__SSE2__)
#warning "Note: AVX and XOP are not enabled.  That's OK."
#elif defined(__x86_64__) || defined(__i386__)
#warning "SSE2 not enabled.  Expect poor performance."
#else
#warning "Note: building generic code for non-x86.  That's OK."
#endif

/*
 * The SSE4 code version has fewer instructions than the SSSE3 version.
 */
#ifdef __SSE4_1__
#warning "Note: SSE4.1 is enabled.  That's great."
#elif defined(__SSE2__)
#warning "SSE4.1 is not enabled.  Performance is OK, but not optimal."
#endif

#include <emmintrin.h>
#include <x86intrin.h>
#include <xmmintrin.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "insecure_memzero.h"
#include "sha256.h"
#include "sysendian.h"
#include "yespower.h"
#include "yespower-platform.c"
#include <smmintrin.h>

/*
 * "Block-mixing" function (modified Salsa20/8 core for yescrypt/yespower):
 *
 *    typedef union {
 *      uint32_t w[16];
 *      uint64_t d[8];
 * #ifdef __SSE2__
 *      __m128i q[4];
 * #endif
 *    } salsa20_blk_t;
 */
typedef union {
	uint32_t w[16];
	uint64_t d[8];
#ifdef __SSE2__
	__m128i q[4];
#endif
} salsa20_blk_t;

/*
 * The permutation context for pwxform (password transform): S-box pointers and
 * block size.
 */
typedef struct {
	uint8_t *S0, *S1, *S2;
	size_t w;
	uint32_t Sbytes;
} pwxform_ctx_t;

#define DECL_SMASK2REG /* empty */
#define MAYBE_MEMORY_BARRIER /* empty */

#ifdef __SSE2__
/*
 * (V)PSRLDQ and (V)PSLLDQ instructions result in multi-cycle shifts.  Use
 * explicit lanes shifts for often-shifted constants.
 */
#define R(z, y, b) do {                              \
    __m128i X = (y);                                 \
    __m128i mask = (__m128i)_mm_set1_epi32(0xff);    \
    X = _mm_slli_epi32(X, (b));                      \
    X = _mm_and_si128(X, (__m128i)_mm_set1_epi8(0x80)); \
    (z) = _mm_or_si128((z), X);                      \
  } while (0)

#define ROR(z, x, b) do {                            \
    __m128i X = _mm_set1_epi32((1U << (b)) - 1);     \
    X = (__m128i)_mm_shuffle_epi8(X, (__m128i)_mm_set1_epi32(0x80808080)); \
    (z) = _mm_or_si128((z), _mm_slli_epi32((x), (b))); \
  } while (0)

#else
#define R(z, y, b) do { (z) |= (uint64_t)(y) << (b); } while (0)
#define ROR(z, x, b) do { (z) |= (uint64_t)((x) & ((1ULL << (b)) - 1)) << (32 + (b)); } while (0)
#endif

/*
 * SALSA20 and blockmix implementations:
 *
 *   SALSA20_8:    8-round Salsa20 core
 *   SALSA20_2:    2-round Salsa20 core (for yescrypt 0.5)
 */
#ifdef __SSE2__
#define SALSA20 SALSA20_8
#else
#define SALSA20 SALSA20_2
#endif

static inline void SALSA20_8(salsa20_blk_t *X)
{
#if defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__))
	__asm__("salta8 (%0)" : "+r"(X)); /* AMD XOP instruction */
#elif defined(__ARM_ACLE__)
	/* no ARM equivalent (we rely on C fallback) */
#else
	uint32_t *x = X->w;
	uint32_t u, v;
#define R(a,b) u = x[(b)] ^ ((x[(a)] << 7)  | (x[(a)] >> (32 - 7))); \
              v = x[(c)] ^ ((x[(d)] << 9)  | (x[(d)] >> (32 - 9))); \
              x[(a)] = u; x[(c)] = v;
	R( 4,  0,  7); R(12,  8,  9);
	R( 9,  5, 13); R( 1, 13, 18);
	R(14, 10,  7); R( 6,  2,  9);
	R( 3, 15, 13); R(11,  7, 18);
#undef R
#define R(a,b) u = x[(b)] ^ ((x[(a)] << 7)  | (x[(a)] >> (32 - 7))); \
              v = x[(c)] ^ ((x[(d)] << 9)  | (x[(d)] >> (32 - 9))); \
              x[(a)] = u; x[(c)] = v;
	R( 1,  0,  7); R(11, 10,  9);
	R( 6,  5, 13); R(14, 15, 18);
	R( 8,  4,  7); R( 2, 13,  9);
	R( 3, 12, 13); R( 9, 14, 18);
#undef R
#endif
}

/* apply Salsa20 core to B */
static inline void salsa20(salsa20_blk_t *restrict B, salsa20_blk_t *restrict Bout)
{
	salsa20_blk_t X;
	memcpy(&X, B, sizeof(X));
	SALSA20_8(&X);
	memcpy(Bout, &X, sizeof(X));
}

/*
 * blockmix_salsa and variants: see yescrypt/yespower specification.
 */
static inline void blockmix_salsa_xor(const salsa20_blk_t *restrict Bin1,
    const salsa20_blk_t *restrict Bin2, salsa20_blk_t *restrict Bout)
{
	salsa20_blk_t X;
	uint64_t *BX = (uint64_t *)&X;
	const uint64_t *in1 = (const uint64_t *)Bin1;
	const uint64_t *in2 = (const uint64_t *)Bin2;
	int i, j;
	/* X = Bin1[last] xor Bin2[last] */
	X.w[ 0] = in1[2 * r - 2] ^ in2[2 * r - 2];
	X.w[ 1] = in1[2 * r - 1] ^ in2[2 * r - 1];
	/* run Salsa20 on X */
	for (i = 0; i < 4; i++) {
		uint64_t u = BX[i * 4 + 0];
		uint64_t v = BX[i * 4 + 1];
		X.w[i * 4 + 0] = u;
		X.w[i * 4 + 1] = v;
	}
	SALSA20_8(&X);
	/* first output element */
	Bout[0] = X;
	j = 1;
	for (i = 0; i < 2 * r - 1; i++) {
		X.w[0] ^= in1[i*2+0];
		X.w[1] ^= in1[i*2+1];
		for (int k = 0; k < 16; k++)
			X.w[k] ^= X.w[k]; /* done in SSE code below */
		SALSA20_8(&X);
		Bout[j++] = X;
	}
}

/* Default blockmix variants for stride=2r */
#define blockmix_salsa_xor_1_0 blockmix_salsa_xor

/* Alias for pass2 (yescrypt 0.5) operations, using SALSA20_2 */

#undef SALSA20
#define SALSA20 SALSA20_2

/**
 * blockmix_salsa(Bin, Bout):
 * Compute Bout = BlockMix_{salsa20, 1}(Bin).  The input Bin must be 128
 * bytes in length; the output Bout must also be the same size.
 */
static inline void blockmix_salsa(const salsa20_blk_t *restrict Bin,
    salsa20_blk_t *restrict Bout)
{
	DECLARE_LOCAL_VARS();
	uint32_t X[16];
	/* X = Bin[last] */
	for (i = 0; i < 16; i++)
		X[i] = le32dec(&Bin[(2*r - 1) * 64 / 4 + i]);
	/* run Salsa20/2 on X */
	salsa20_simd_shuffle(((const salsa20_blk_t*)X) + 0, (salsa20_blk_t*)X);
	/* Bout[0] = X xor Bin[0] */
	for (i = 0; i < 16; i++)
		le32enc(&Bout[0].w[i], X[i] ^ le32dec(&Bin[i]));
	for (j = 1; j < 2*r; j++) {
		uint32_t t[16];
		for (i = 0; i < 16; i++)
			t[i] = le32dec(&Bin[j * 64 / 4 + i]);
		/* X = X xor t, then Salsa20/2 */
		for (i = 0; i < 16; i++)
			X[i] ^= t[i];
		salsa20_simd_shuffle(((const salsa20_blk_t*)X) + 0, (salsa20_blk_t*)X);
		for (i = 0; i < 16; i++)
			le32enc(&Bout[j].w[i], X[i]);
	}
}

/**
 * blockmix_salsa_xor(Bin1, Bin2, Bout):
 * Compute Bout = BlockMix_{salsa20, 1}(Bin1 XOR Bin2).
 * Bout must be 128 bytes long.
 */
static inline void blockmix_salsa_xor_1_0(const salsa20_blk_t *restrict Bin1,
    const salsa20_blk_t *restrict Bin2, salsa20_blk_t *restrict Bout)
{
	salsa20_blk_t X;
	/* X = Bin1[last] XOR Bin2[last] */
	X.w[ 0] = Bin1[(2*r - 1) * 16 + 0] ^ Bin2[(2*r - 1) * 16 + 0];
	X.w[ 1] = Bin1[(2*r - 1) * 16 + 1] ^ Bin2[(2*r - 1) * 16 + 1];
	/* run Salsa20/2 on X */
	salsa20_simd_shuffle(&X, &X);
	/* Bout[0] = X xor Bin2[0] */
	for (i = 0; i < 16; i++)
		Bout[0].w[i] = X.w[i] ^ Bin2[0].w[i];
	j = 1;
	for (i = 0; i < 2 * r - 1; i++) {
		/* X = X xor Bin1[i] */
		for (int k = 0; k < 16; k++)
			X.w[k] ^= Bin1[i*16 + k];
		salsa20_simd_shuffle(&X, &X);
		for (k = 0; k < 16; k++)
			Bout[j].w[k] = X.w[k] ^ Bin2[j*16 + k];
		j++;
	}
}

/**
 * blockmix_xor_save(Bin1, Bin2, Bout, V, index):
 * Compute Bout = BlockMix_{salsa20, 1}(Bin1 XOR Bin2),
 * but also save the first output element into V[index].
 */
static inline void blockmix_xor_save_1_0(const salsa20_blk_t *restrict Bin1,
    const salsa20_blk_t *restrict Bin2, salsa20_blk_t *restrict Bout,
    salsa20_blk_t *V, uint64_t index)
{
	salsa20_blk_t X;
	/* X = Bin1[last] xor Bin2[last] */
	X = Bin1[(2*r - 1)];
	XorXor(X, Bin2[(2*r - 1)], X);
	SALSA20(&X);
	Bout[0] = X;
	V[index] = X;
	for (i = 1; i < 2 * r; i++) {
		for (j = 0; j < 16; j++)
			X.w[j] ^= Bin1[(i - 1)].w[j];
		SALSA20(&X);
		Bout[i] = X;
	}
}

/*
 * Yespower smix implementations for 0.5 (smix1, smix2) and 1.0 (smix1_1_0, smix2_1_0).
 * These include the XOR and pwxform steps from yespower.
 */
void smix1_1_0(uint32_t *B, uint32_t r, uint32_t N, uint32_t Nloop,
    uint32_t *V, salsa20_blk_t *XY, pwxform_ctx_t *ctx)
{
	uint32_t i, j;
	salsa20_blk_t X;
	salsa20_blk_t Y[1024];
	salsa20_blk_t *Xptr = &X;
	for (i = 0; i < (uint32_t)(Nloop ? N : N); i += Nloop ? 1 : N) {
		/* BlockMix with saving: */
		blockmix_xor_save_1_0((const salsa20_blk_t*)B,
		                     (const salsa20_blk_t*)B,
		                     (salsa20_blk_t*)XY,
		                     V + i*(2*r), i);
		B = (uint32_t*)XY;
	}
}

void smix2_1_0(uint32_t *B, uint32_t r, uint32_t N, uint32_t Nloop,
    uint32_t *V, salsa20_blk_t *XY, pwxform_ctx_t *ctx)
{
	uint32_t i, j, n, w;
	uint32_t *X = (uint32_t*)XY;
	salsa20_blk_t *Y = (salsa20_blk_t*)(XY + 16*2*r);
	uint32_t Vj;
	for (j = 0; j < 2*r; j++)
		for (i = 0; i < 2*r; i++)
			XY[j*2*r + i].w[k] = 0;
	while (1) {
		/* Random indexing */
		if (--Nloop == 0) break;
		n = X[(n_index)*i];
		n &= (N - 1);
		Vj = n;
		blockmix_xor((salsa20_blk_t*)&X[(2*r - 1)*16], V + Vj*2*r, (salsa20_blk_t*)XY, r, ctx);
		for (i = 0; i < 2*r; i++)
			X[i] ^= XY[i];
	}
}

#undef _YESPOWER_OPT_C_PASS_
#define _YESPOWER_OPT_C_PASS_ 2
#define blockmix_salsa blockmix_salsa_1_0
#define blockmix_salsa_xor blockmix_salsa_xor_1_0
#define blockmix blockmix_1_0
#define blockmix_xor blockmix_xor_1_0
#define blockmix_xor_save blockmix_xor_save_1_0
#define smix1 smix1_1_0
#define smix2 smix2_1_0
#define smix smix_1_0
#include "yespower-opt.c"
#undef smix

/**
 * yespower(local, src, srclen, params, dst):
 * Compute yespower(src[0 .. srclen - 1], params->N, params->r),
 * putting the 256-bit hash result into dst.
 * local is the thread-local RAM/context structure (yespower_local_t).
 * This implementation returns 0 on success, -1 on error.
 */
int yespower(yespower_local_t *local,
    const uint8_t *src, size_t srclen,
    const yespower_params_t *params,
    yespower_binary_t *dst)
{
	const yespower_version_t version = params->version;
	uint32_t N = params->N;
	uint32_t r = params->r;
	const uint8_t *pers = params->pers;
	size_t perslen = params->perslen;
	uint32_t Swidth;
	size_t B_size, V_size, XY_size, need;
	uint8_t *B, *S;
	salsa20_blk_t *V, *XY;
	pwxform_ctx_t ctx;
	uint8_t sha256[32];

	/* Sanity-check parameters */
	if ((version != YESPOWER_0_5 && version != YESPOWER_1_0) ||
	    N < 1024 || N > 512 * 1024 || r < 8 || r > 32 ||
	    (N & (N - 1)) != 0 ||
	    (!pers && perslen)) {
		return -1;
	}

	/* If pers is provided and we use YESPOWER_1_0, we require exactly 32 bytes */
	if (version == YESPOWER_1_0 && perslen != 32) {
		return -1;
	}

	/* For version 0.5, ignore pers: it's always "password" = coinbase */
	if (version == YESPOWER_0_5) {
		pers = NULL;
		perslen = 0;
	}

	/*
	 * The memory layout for yespower:
	 *   B: 128*r*N bytes   (the scrypt buffer)
	 *   V: 128*r*N bytes   (the scrypt V array, used and freed within smix)
	 *  XY: 128*(r+1)*N bytes (temporary)
	 * S: depends on Swidth = N * 128 bytes (YESPOWER_1_0 only)
	 */

	B_size = (size_t)128 * r * N;
	V_size = B_size;
	XY_size = (size_t)128 * (r + 1) * N;
	/* For YESPOWER_1_0, allocate extra 1 block of SXOR for passwordMix */
	Swidth = version == YESPOWER_1_0 ? N * 128 * 4 : 0;
	need = B_size + V_size + XY_size + Swidth;

	if (need / 128 / r != (size_t)N * (2 * (r + 1) + 2 * r)) {
		/* overflow or too large */
		return -1;
	}

	/* allocate memory */
	B = malloc(B_size);
	S = malloc(Swidth);
	V = (salsa20_blk_t*)malloc(V_size);
	XY = (salsa20_blk_t*)malloc(XY_size);
	if (!B || (Swidth && !S) || !V || !XY) {
		free(B);
		free(S);
		free(V);
		free(XY);
		return -1;
	}
	local->base = B;
	local->base_size = B_size;
	local->aligned = S;
	local->aligned_size = Swidth;

	/* 1. B = SHA256(src || pers || srclen) */
	sha256_begin(&sha256);
	sha256_update(&sha256, src, srclen);
	if (pers) {
		sha256_update(&sha256, pers, perslen);
	}
	sha256_end(&sha256);
	memcpy(B, sha256, 32);
	memset((uint8_t*)B + 32, 0, 128 * r - 32);

	/* 2. yescrypt into B, possibly with S */
	if (version == YESPOWER_1_0) {
		/*
		 * Derive S-box data (Swidth bytes) from the SHA256 output.
		 * We want Swidth bytes of random data derived from sha256 output.
		 * This is treated like a password mix (S-box).
		 */
		uint8_t Sha256_S[32];
		sha256_begin(Sha256_S);
		sha256_update(Sha256_S, sha256, 32);
		sha256_end(Sha256_S);
		memset(S, 0, Swidth);
		memcpy(S, Sha256_S, 32);
	}

	yescrypt_ror0_256(local, B, r, N, 1, S, Swidth);

	/* 3. XOR with 32-bit word, then final SHA256: F = SHA256(B) */
	/* (This step is not used by all coins; adjust if needed) */
	if (dst) {
		/* final Blake2b-256 (optional) */
		memcpy(dst->uc, B, 32);
	}

	/* free memory */
	free(B);
	free(S);
	free(V);
	free(XY);

	return 0;
}

int yespower_init_local(yespower_local_t *local)
{
	init_region(local);
	return 0;
}

int yespower_free_local(yespower_local_t *local)
{
	return free_region(local);
}
#endif
