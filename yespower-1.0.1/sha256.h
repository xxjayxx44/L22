#ifndef _SHA256_H_
#define _SHA256_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Avoid namespace collisions */
#define SHA256_Init         libcperciva_SHA256_Init
#define SHA256_Update       libcperciva_SHA256_Update
#define SHA256_Final        libcperciva_SHA256_Final
#define SHA256_Buf          libcperciva_SHA256_Buf
#define SHA256_CTX          libcperciva_SHA256_CTX
#define HMAC_SHA256_Init    libcperciva_HMAC_SHA256_Init
#define HMAC_SHA256_Update  libcperciva_HMAC_SHA256_Update
#define HMAC_SHA256_Final   libcperciva_HMAC_SHA256_Final
#define HMAC_SHA256_Buf     libcperciva_HMAC_SHA256_Buf
#define HMAC_SHA256_CTX     libcperciva_HMAC_SHA256_CTX

/* Context structure for SHA256 operations */
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buf[64];
} SHA256_CTX;

/* Initialize a SHA256 context */
void SHA256_Init(SHA256_CTX *restrict ctx)
    __attribute__((nonnull));

/* Process len bytes from in into SHA256 context ctx */
void SHA256_Update(SHA256_CTX *restrict ctx, const void *restrict in, size_t len)
    __attribute__((nonnull(1,2)));

/* Finalize SHA256 digest; digest must be at least 32 bytes */
void SHA256_Final(uint8_t digest[static 32], SHA256_CTX *restrict ctx)
    __attribute__((nonnull(1,2)));

/* Compute SHA256 of in (len bytes) and write result to digest */
void SHA256_Buf(const void *restrict in, size_t len, uint8_t digest[static 32])
    __attribute__((nonnull(1,3)));

/* Context structure for HMAC-SHA256 operations */
typedef struct {
    SHA256_CTX ictx;
    SHA256_CTX octx;
} HMAC_SHA256_CTX;

/* Initialize HMAC-SHA256 context with key K of length Klen */
void HMAC_SHA256_Init(HMAC_SHA256_CTX *restrict ctx, const void *restrict K, size_t Klen)
    __attribute__((nonnull(1,2)));

/* Process len bytes from in into HMAC-SHA256 context ctx */
void HMAC_SHA256_Update(HMAC_SHA256_CTX *restrict ctx, const void *restrict in, size_t len)
    __attribute__((nonnull(1,2)));

/* Finalize HMAC-SHA256 digest; digest must be at least 32 bytes */
void HMAC_SHA256_Final(uint8_t digest[static 32], HMAC_SHA256_CTX *restrict ctx)
    __attribute__((nonnull(1,2)));

/* Compute HMAC-SHA256 of in (len bytes) using key K of length Klen */
void HMAC_SHA256_Buf(const void *restrict K, size_t Klen,
                     const void *restrict in, size_t len, uint8_t digest[static 32])
    __attribute__((nonnull(1,3,5)));

/* Compute PBKDF2-HMAC-SHA256 derived key.
 * The derived key length dkLen must be at most 32 * (2^32 - 1).
 */
void PBKDF2_SHA256(const uint8_t *restrict passwd, size_t passwdlen,
                   const uint8_t *restrict salt, size_t saltlen,
                   uint64_t c, uint8_t *restrict buf, size_t dkLen)
    __attribute__((nonnull(1,3,6)));

#ifdef __cplusplus
}
#endif

#endif /* !_SHA256_H_ */
