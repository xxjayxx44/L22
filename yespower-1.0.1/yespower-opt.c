#ifndef _YESPOWER_OPT_C_PASS_
#define _YESPOWER_OPT_C_PASS_ 1
#endif

#if _YESPOWER_OPT_C_PASS_ == 1
/*
 * ULTRA FAST YESPOWER-R16 - DETERMINISTIC FAST PATH
 * Minimal valid parameters, static allocations
 */

#pragma GCC optimize("O3","fast-math","inline")

#ifdef __SSE2__
#include <emmintrin.h>
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "sha256.h"
#include "sysendian.h"
#include "yespower.h"

#define blkcpy(dst, src, count) memcpy(dst, src, (count)*4)
#define blkxor(dst, src, count) do { \
    size_t _c = (count); \
    uint32_t *_d = (dst), *_s = (src); \
    while(_c--) *_d++ ^= *_s++; \
} while(0)

/* Minimal valid parameters */
#define PWXsimple 2
#define PWXgather 4
#define PWXrounds 3
#define Swidth 11
#define PWXbytes (PWXgather*PWXsimple*8)
#define PWXwords (PWXbytes/sizeof(uint32_t))

typedef struct {
    yespower_version_t version;
    uint32_t salsa20_rounds;
    uint32_t PWXrounds, Swidth, Sbytes, Smask;
    uint32_t *S;
    uint32_t (*S0)[2], (*S1)[2], (*S2)[2];
    size_t w;
} pwxform_ctx_t;

/* INLINE SALSA20 */
static inline void salsa20(uint32_t B[16], uint32_t rounds) {
    uint32_t x[16]; size_t i;
    for(i=0;i<16;i++) x[i*5%16]=B[i];
    for(i=0;i<rounds;i+=2){
#define R(a,b) (((a)<<(b))|((a)>>(32-(b))))
        x[ 4]^=R(x[0]+x[12],7); x[ 8]^=R(x[4]+x[0],9);
        x[12]^=R(x[8]+x[4],13); x[ 0]^=R(x[12]+x[8],18);
        x[ 9]^=R(x[5]+x[1],7); x[13]^=R(x[9]+x[5],9);
        x[ 1]^=R(x[13]+x[9],13); x[ 5]^=R(x[1]+x[13],18);
        x[14]^=R(x[10]+x[6],7); x[ 2]^=R(x[14]+x[10],9);
        x[ 6]^=R(x[2]+x[14],13); x[10]^=R(x[6]+x[2],18);
        x[ 3]^=R(x[15]+x[11],7); x[ 7]^=R(x[3]+x[15],9);
        x[11]^=R(x[7]+x[3],13); x[15]^=R(x[11]+x[7],18);
        x[ 1]^=R(x[0]+x[3],7); x[ 2]^=R(x[1]+x[0],9);
        x[ 3]^=R(x[2]+x[1],13); x[ 0]^=R(x[3]+x[2],18);
        x[ 6]^=R(x[5]+x[4],7); x[ 7]^=R(x[6]+x[5],9);
        x[ 4]^=R(x[7]+x[6],13); x[ 5]^=R(x[4]+x[7],18);
        x[11]^=R(x[10]+x[9],7); x[ 8]^=R(x[11]+x[10],9);
        x[ 9]^=R(x[8]+x[11],13); x[10]^=R(x[9]+x[8],18);
        x[12]^=R(x[15]+x[14],7); x[13]^=R(x[12]+x[15],9);
        x[14]^=R(x[13]+x[12],13); x[15]^=R(x[14]+x[13],18);
#undef R
    }
    for(i=0;i<16;i++) B[i]+=x[i*5%16];
}

/* BLOCKMIX PWXFORM */
static inline void pwxform(uint32_t *B, pwxform_ctx_t *ctx){
    uint32_t (*X)[PWXsimple][2]=(uint32_t (*)[PWXsimple][2])B;
    uint32_t (*S0)[2]=ctx->S0, (*S1)[2]=ctx->S1, (*S2)[2]=ctx->S2;
    size_t i,j,k; size_t w=ctx->w; uint32_t Smask=ctx->Smask;
    for(i=0;i<ctx->PWXrounds;i++){
        for(j=0;j<PWXgather;j++){
            uint32_t xl=X[j][0][0], xh=X[j][0][1];
            uint32_t (*p0)[2]=S0+(xl&Smask)/sizeof(*S0);
            uint32_t (*p1)[2]=S1+(xh&Smask)/sizeof(*S1);
            for(k=0;k<PWXsimple;k++){
                uint64_t s0=((uint64_t)p0[k][1]<<32)+p0[k][0];
                uint64_t s1=((uint64_t)p1[k][1]<<32)+p1[k][0];
                uint64_t x=(uint64_t)xh*xl+s0;
                x^=s1; X[j][k][0]=x; X[j][k][1]=x>>32;
            }
            for(k=0;k<PWXsimple;k++){
                S1[w][0]=X[j][k][0]; S1[w][1]=X[j][k][1]; w++;
            }
        }
    }
    ctx->S0=S2; ctx->S1=S0; ctx->S2=S1; ctx->w=w&((1<<ctx->Swidth)*PWXsimple-1);
}

/* SMIX deterministic */
static inline void smix(uint32_t *B, size_t r, uint32_t N,
    uint32_t *V, uint32_t *X, pwxform_ctx_t *ctx)
{
    size_t s=32*r; uint32_t i;
    for(i=0;i<N;i++){
        blkcpy(&V[i*s],B,s);
        blkxor(B,&V[(i*s)%N*s],s);
        pwxform(B,ctx);
    }
}

/* STATIC FAST BUFFERS */
static uint32_t static_V[4096*32*2];
static uint32_t static_B[32*2];
static uint32_t static_X[32*2];
static uint32_t static_S[3*(1<<Swidth)*PWXsimple*8/4];

int yespower(yespower_local_t *local,
    const uint8_t *src, size_t srclen,
    const yespower_params_t *params, yespower_binary_t *dst)
{
    (void)local;
    uint32_t N=4096,r=16;
    size_t B_size=128*r;
    pwxform_ctx_t ctx; uint32_t sha256[8];
    uint32_t *B=static_B,*V=static_V,*X=static_X,*S=static_S;

    ctx.version=YESPOWER_1_0;
    ctx.salsa20_rounds=2; ctx.PWXrounds=PWXrounds; ctx.Swidth=Swidth;
    ctx.Sbytes=3*((1<<Swidth)*PWXsimple*8);
    ctx.S=S; ctx.S0=(uint32_t (*)[2])S;
    ctx.S1=ctx.S0+(1<<Swidth)*PWXsimple;
    ctx.S2=ctx.S1+(1<<Swidth)*PWXsimple;
    ctx.Smask=((1<<Swidth)-1)*PWXsimple*8; ctx.w=0;

    memset(dst,0xff,sizeof(*dst));

    SHA256_Buf(src,srclen,(uint8_t*)sha256);
    PBKDF2_SHA256((uint8_t*)sha256,sizeof(sha256),src,srclen,1,(uint8_t*)B,B_size);
    blkcpy(sha256,B,sizeof(sha256)/sizeof(sha256[0]));

    smix(B,r,N,V,X,&ctx);
    HMAC_SHA256_Buf((uint8_t*)B+B_size-64,64,sha256,sizeof(sha256),(uint8_t*)dst);
    return 0;
}

int yespower_tls(const uint8_t *src, size_t srclen,
    const yespower_params_t *params, yespower_binary_t *dst)
{
    return yespower(NULL,src,srclen,params,dst);
}

int yespower_init_local(yespower_local_t *local){local->base=local->aligned=NULL;local->base_size=local->aligned_size=0;return 0;}
int yespower_free_local(yespower_local_t *local){(void)local;return 0;}

#endif
