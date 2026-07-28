/* twine_bitslice.c - TWINE-128 Bitslice (SSSE3) */
#include "twine.h"
#if defined(_MSC_VER)
  #include <intrin.h>
#else
  #include <x86intrin.h>
#endif
#include <tmmintrin.h>
#include <emmintrin.h>

static const uint8_t SB[16]={0xc,0x0,0xf,0xa,0x2,0xb,0x9,0x5,0x8,0x3,0xd,0x7,0x1,0xe,0x6,0x4};
static const uint8_t RC[36]={0x01,0x02,0x04,0x08,0x10,0x20,0x03,0x06,0x0c,0x18,0x13,0x05,0x0a,0x14,0x0b,0x16,0x2c,0x1b,0x36,0x2f,0x1d,0x3a,0x37,0x2d,0x1b,0x36,0x2f,0x1d,0x3a,0x37,0x2d,0x1b,0x36,0x2f,0x1d,0x3a};

void twine_bitslice_init(twine_ctx *ctx,const uint8_t *key){
    uint16_t W[8];
    for(int i=0;i<8;i++)W[i]=(uint16_t)((key[2*i]<<8)|key[2*i+1]);
    for(int r=0;r<36;r++){
        uint32_t rk=((uint32_t)W[1]<<16)|(W[3]&0xFFFFU);
        uint8_t rc=RC[r];rk^=((uint32_t)rc<<12)^((uint32_t)rc<<4);
        ctx->rk[r]=rk;
        uint16_t t=W[0];for(int j=0;j<7;j++)W[j]=W[j+1];W[7]=t;
        uint16_t w7=W[7];
        W[7]=(uint16_t)((SB[(w7>>12)&0xF]<<12)|(SB[(w7>>8)&0xF]<<8)|(SB[(w7>>4)&0xF]<<4)|SB[w7&0xF]);
    }
}

void twine_bitslice_encrypt(const uint8_t *pt,uint8_t *ct,const twine_ctx *ctx){
    uint8_t B[16];
    for(int i=0;i<8;i++){B[2*i]=(pt[i]>>4)&0xF;B[2*i+1]=pt[i]&0xF;}
    for(int r=0;r<36;r++){
        uint32_t rk=ctx->rk[r];
        for(int i=0;i<8;i++)B[i]=SB[B[i]];
        for(int i=0;i<8;i++)B[i+8]^=B[i];
        uint8_t t=B[0];for(int i=0;i<15;i++)B[i]=B[i+1];B[15]=t;
        for(int i=0;i<8;i++)B[i]^=(uint8_t)((rk>>(28-4*i))&0xF);
    }
    for(int i=0;i<8;i++)ct[i]=(uint8_t)((B[2*i]<<4)|B[2*i+1]);
}

void twine_bitslice_encrypt_x4(const uint8_t pt[4][8],uint8_t ct[4][8],const twine_ctx *ctx){
    for(int i=0;i<4;i++)twine_bitslice_encrypt(pt[i],ct[i],ctx);
}
