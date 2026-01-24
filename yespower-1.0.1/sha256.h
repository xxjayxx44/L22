/*-
 * Copyright 2005-2016 Colin Percival
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
 */

#ifndef LIBCPERCIVA_SHA256_H
#define LIBCPERCIVA_SHA256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* =========================
 * SHA256 context
 * ========================= */
typedef struct {
	uint32_t state[8];
	uint64_t count;
	uint8_t  buf[64];
} SHA256_CTX;

/* =========================
 * SHA256 API
 * ========================= */
void SHA256_Init(SHA256_CTX *ctx);
void SHA256_Update(SHA256_CTX *ctx, const void *data, size_t len);
void SHA256_Final(uint8_t digest[32], SHA256_CTX *ctx);
void SHA256_Buf(const void *data, size_t len, uint8_t digest[32]);

/* =========================
 * HMAC-SHA256 context
 * ========================= */
typedef struct {
	SHA256_CTX ictx;
	SHA256_CTX octx;
} HMAC_SHA256_CTX;

/* =========================
 * HMAC-SHA256 API
 * ========================= */
void HMAC_SHA256_Init(HMAC_SHA256_CTX *ctx, const void *key, size_t keylen);
void HMAC_SHA256_Update(HMAC_SHA256_CTX *ctx, const void *data, size_t len);
void HMAC_SHA256_Final(uint8_t digest[32], HMAC_SHA256_CTX *ctx);
void HMAC_SHA256_Buf(const void *key, size_t keylen,
                     const void *data, size_t len,
                     uint8_t digest[32]);

/* =========================
 * PBKDF2-HMAC-SHA256
 * ========================= */
void PBKDF2_SHA256(const uint8_t *passwd, size_t passwdlen,
                   const uint8_t *salt, size_t saltlen,
                   uint64_t c,
                   uint8_t *buf, size_t dkLen);

#ifdef __cplusplus
}
#endif

#endif /* LIBCPERCIVA_SHA256_H */
