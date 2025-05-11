/* yespower-opt-n4020.c
 * Full SSE2-only, Atom-tuned yespower implementation
 * Supports YESPOWER_0_5 and YESPOWER_1_0, r >= 1
 * Drop AVX/XOP paths, tune scheduling for Intel Atom (N4020)
 */

typedef struct {
    uint8_t *S0, *S1, *S2;
    size_t w;
    uint32_t Sbytes;
} pwxform_ctx_t;


#ifndef _YESPOWER_OPT_C_PASS_
#define _YESPOWER_OPT_C_PASS_ 1
#endif

/* N4020 optimizations */
#undef __XOP__
#undef __AVX__
#if defined(__GNUC__) && (__GNUC__ >= 6)
#pragma GCC target("tune=atom")
#endif

#if _YESPOWER_OPT_C_PASS_ == 1

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <emmintrin.h>    /* SSE2 intrinsics */
#include "insecure_memzero.h"
#include "sha256.h"
#include "sysendian.h"
#include "yespower.h"
#include "yespower-platform.c"

#if __STDC_VERSION__ >= 199901L
#elif defined(__GNUC__)
#define restrict __restrict
#else
#define restrict
#endif

#ifdef __GNUC__
#define unlikely(x) __builtin_expect(!!(x),0)
#else
#define unlikely(x) (x)
#endif

#define PREFETCH(addr) _mm_prefetch((const char*)(addr), _MM_HINT_T0)

/* Salsa20 block type */
typedef union {
    uint32_t w[16];
    uint64_t d[8];
    __m128i   q[4];
} salsa20_blk_t;

static inline void salsa20_simd_shuffle(const salsa20_blk_t *in, salsa20_blk_t *out) {
    out->d[0] = in->w[0]  | ((uint64_t)in->w[5]  <<32);
    out->d[1] = in->w[10] | ((uint64_t)in->w[15] <<32);
    out->d[2] = in->w[5]  | ((uint64_t)in->w[10] <<32);
    out->d[3] = in->w[15] | ((uint64_t)in->w[0]  <<32);
    out->d[4] = in->w[3]  | ((uint64_t)in->w[8]  <<32);
    out->d[5] = in->w[12] | ((uint64_t)in->w[7]  <<32);
    out->d[6] = in->w[8]  | ((uint64_t)in->w[3]  <<32);
    out->d[7] = in->w[7]  | ((uint64_t)in->w[12] <<32);
}

static inline void salsa20_simd_unshuffle(const salsa20_blk_t *in, salsa20_blk_t *out) {
    out->w[0]  =  in->d[0]        &0xFFFFFFFF;
    out->w[5]  =  in->d[0] >>32;
    out->w[10] =  in->d[1]        &0xFFFFFFFF;
    out->w[15] =  in->d[1] >>32;
    out->w[5]  =  in->d[2]        &0xFFFFFFFF;
    out->w[10] =  in->d[2] >>32;
    out->w[15] =  in->d[3]        &0xFFFFFFFF;
    out->w[0]  =  in->d[3] >>32;
    out->w[3]  =  in->d[4]        &0xFFFFFFFF;
    out->w[8]  =  in->d[4] >>32;
    out->w[12] =  in->d[5]        &0xFFFFFFFF;
    out->w[7]  =  in->d[5] >>32;
    out->w[8]  =  in->d[6]        &0xFFFFFFFF;
    out->w[3]  =  in->d[6] >>32;
    out->w[7]  =  in->d[7]        &0xFFFFFFFF;
    out->w[12] =  in->d[7] >>32;
}

#define DECL_X __m128i X0,X1,X2,X3;
#define LOAD_X(b)  X0=(b).q[0];X1=(b).q[1];X2=(b).q[2];X3=(b).q[3];
#define SAVE_X(b) (b).q[0]=X0;(b).q[1]=X1;(b).q[2]=X2;(b).q[3]=X3;

#define ARX(a,b,c,s) { __m128i t=_mm_add_epi32(b,c); a=_mm_xor_si128(a,_mm_slli_epi32(t,s)); a=_mm_xor_si128(a,_mm_srli_epi32(t,32-s)); }

#define SALSA20_8ROUNDS { \
    ARX(X1,X0,X3,7);ARX(X2,X1,X0,9);ARX(X3,X2,X1,13);ARX(X0,X3,X2,18); \
    X1=_mm_shuffle_epi32(X1,0x93);X2=_mm_shuffle_epi32(X2,0x4E);X3=_mm_shuffle_epi32(X3,0x39); \
    ARX(X3,X0,X1,7);ARX(X2,X3,X0,9);ARX(X1,X2,X3,13);ARX(X0,X1,X2,18); \
    X1=_mm_shuffle_epi32(X1,0x39);X2=_mm_shuffle_epi32(X2,0x4E);X3=_mm_shuffle_epi32(X3,0x93); \
    ARX(X1,X0,X3,7);ARX(X2,X1,X0,9);ARX(X3,X2,X1,13);ARX(X0,X3,X2,18); \
    X1=_mm_shuffle_epi32(X1,0x93);X2=_mm_shuffle_epi32(X2,0x4E);X3=_mm_shuffle_epi32(X3,0x39); \
    ARX(X3,X0,X1,7);ARX(X2,X3,X0,9);ARX(X1,X2,X3,13);ARX(X0,X1,X2,18); \
    X1=_mm_shuffle_epi32(X1,0x39);X2=_mm_shuffle_epi32(X2,0x4E);X3=_mm_shuffle_epi32(X3,0x93); }

static inline void salsa20_xor(const salsa20_blk_t *inp, salsa20_blk_t *st) {
    DECL_X; LOAD_X(*st);
    X0=_mm_xor_si128(X0,inp->q[0]);X1=_mm_xor_si128(X1,inp->q[1]);X2=_mm_xor_si128(X2,inp->q[2]);X3=_mm_xor_si128(X3,inp->q[3]);
    SALSA20_8ROUNDS;
    X0=_mm_add_epi32(X0,inp->q[0]);X1=_mm_add_epi32(X1,inp->q[1]);X2=_mm_add_epi32(X2,inp->q[2]);X3=_mm_add_epi32(X3,inp->q[3]);
    SAVE_X(*st);
}

static inline void blockmix_salsa(const salsa20_blk_t *restrict Bin, salsa20_blk_t *restrict Bout) {
    Bout[0]=Bin[1]; salsa20_xor(&Bin[0],&Bout[0]);
    salsa20_xor(&Bin[1],&Bout[1]);
}

static inline uint32_t blockmix_salsa_xor(const salsa20_blk_t *B1, const salsa20_blk_t *B2, salsa20_blk_t *Bout) {
    salsa20_blk_t T; T=B1[1];
    T.q[0]=_mm_xor_si128(B1[1].q[0],B2[1].q[0]);
    T.q[1]=_mm_xor_si128(B1[1].q[1],B2[1].q[1]);
    T.q[2]=_mm_xor_si128(B1[1].q[2],B2[1].q[2]);
    T.q[3]=_mm_xor_si128(B1[1].q[3],B2[1].q[3]);
    salsa20_xor(&B2[0],&T); Bout[0]=T;
    salsa20_xor(&B1[1],&T); salsa20_xor(&B2[1],&Bout[1]);
    return (uint32_t)_mm_cvtsi128_si32(Bout[1].q[0]);
}

static inline uint32_t integerify(const salsa20_blk_t *B, size_t r) { (void)r; return (uint32_t)_mm_cvtsi128_si32(B[2*r-1].q[0]); }

static void smix1(uint8_t *B, size_t r, uint32_t N, salsa20_blk_t *V, salsa20_blk_t *XY, void *ctx) {
    size_t s=2*r; salsa20_blk_t *X=V, *Y=V+s;
    for(size_t i=0;i<2*r;i++){ uint32_t *src=(uint32_t*)(B+64*i); for(int k=0;k<16;k++) X[i].w[k]=le32dec(&src[k]); salsa20_simd_shuffle(&X[i],&X[i]); }
    blockmix_salsa(X,Y); blockmix_salsa(Y,X);
    for(uint32_t i=0;i<2*r;i++) V[i]=X[i];
    uint32_t j=integerify(X,r)&(N-1);
    for(uint32_t n=2;n<N;n<<=1){ uint32_t idx=j; blockmix_salsa_xor(&V[idx*r],&V[idx*r+s],X); j=integerify(X,r)&(n-1); }
    for(size_t i=0;i<2*r;i++) salsa20_simd_unshuffle(&X[i],(salsa20_blk_t*)(B+64*i));
}

static void smix2(uint8_t *B, size_t r, uint32_t N, uint32_t Nloop, salsa20_blk_t *V, salsa20_blk_t *XY, void *ctx) {
    size_t s=2*r; salsa20_blk_t *X=XY, *Y=XY+s;
    for(size_t i=0;i<2*r;i++){ uint32_t *src=(uint32_t*)(B+64*i); for(int k=0;k<16;k++) X[i].w[k]=le32dec(&src[k]); salsa20_simd_shuffle(&X[i],&X[i]); }
    uint32_t j=integerify(X,r)&(N-1);
    while(Nloop>1){ blockmix_salsa_xor(&V[j*s],&X[0],Y); blockmix_salsa_xor(&V[j*s],&X[1],Y+1); X[0]=Y[0]; X[1]=Y[1]; j=integerify(X,r)&(N-1); Nloop-=2; }
    for(size_t i=0;i<2*r;i++) salsa20_simd_unshuffle(&X[i],(salsa20_blk_t*)(B+64*i));
}

static void smix(uint8_t *B, size_t r, uint32_t N, salsa20_blk_t *V, salsa20_blk_t *XY, void *ctx) {
    uint32_t Nloop=((N+2)/3); if(Nloop&1) Nloop++;
    smix1(B,r,N,V,XY,ctx);
    smix2(B,r,N,Nloop,V,XY,ctx);
}

int yespower(yespower_local_t *local, const uint8_t *src, size_t srclen, const yespower_params_t *params, yespower_binary_t *dst) {
    yespower_version_t version=params->version; uint32_t N=params->N, r=params->r; const uint8_t *pers=params->pers; size_t perslen=params->perslen;
    if((version!=YESPOWER_0_5&&version!=YESPOWER_1_0)||N<1024||N>512*1024||(N&(N-1))!=0||r<1||r>32||(r&(r-1))!=0||(version==YESPOWER_1_0&&(!pers&&perslen))) { errno=EINVAL; goto fail; }
    size_t Bsize=128*r, Vsize=Bsize*N, XYsize= (version==YESPOWER_0_5?2*Bsize:Bsize+64);
    size_t Swidth=(version==YESPOWER_0_5?8:11);
    size_t Sbytes=(version==YESPOWER_0_5?2*((1<<Swidth)*2*8):3*((1<<Swidth)*2*8));
    size_t need=Bsize+Vsize+XYsize+Sbytes;
    if(local->aligned_size<need){ if(free_region(local)) goto fail; if(!alloc_region(local,need)) goto fail; }
    uint8_t *B=(uint8_t*)local->aligned; salsa20_blk_t *V=(salsa20_blk_t*)(B+Bsize); salsa20_blk_t *XY=(salsa20_blk_t*)(B+Bsize+Vsize); uint8_t *S=(uint8_t*)XY+XYsize;
    uint8_t *S0=S, *S1=S+((1<<Swidth)*2*8), *S2=(version==YESPOWER_1_0?S1+((1<<Swidth)*2*8):NULL);
    pwxform_ctx_t ctx={S0,S1,S2, (uint32_t)Bsize};
    uint8_t sha[32]; SHA256_Buf(src,srclen,sha);
    if(version==YESPOWER_0_5){ PBKDF2_SHA256(sha,32,src,srclen,1,B,Bsize); memcpy(sha,B,32); smix(B,r,N,V,XY,&ctx); PBKDF2_SHA256(sha,32,B,Bsize,1,(uint8_t*)dst,sizeof(*dst)); if(pers){ HMAC_SHA256_Buf(dst,sizeof(*dst),pers,perslen,sha); SHA256_Buf(sha,sha,dst); } }
    else{ if(pers){ src=pers; srclen=perslen;} PBKDF2_SHA256(sha,32,src,srclen,1,B,128); memcpy(sha,B,32); smix(B,r,N,V,XY,&ctx); HMAC_SHA256_Buf(B+Bsize-64,64,sha,32,(uint8_t*)dst); }
    return 0;
fail: if(dst) memset(dst,0xFF,sizeof(*dst)); return -1;
}

int yespower_tls(const uint8_t *src,size_t srclen,const yespower_params_t *params,yespower_binary_t *dst){ static __thread yespower_local_t local; static __thread int init=0; if(!init){ init_region(&local); init=1;} return yespower(&local,src,srclen,params,dst); }

int yespower_init_local(yespower_local_t *local){ init_region(local); return 0; }
int yespower_free_local(yespower_local_t *local){ return free_region(local); }

#endif /* _YESPOWER_OPT_C_PASS_ */
