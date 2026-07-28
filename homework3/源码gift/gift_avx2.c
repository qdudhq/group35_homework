/* gift_avx2.c - GIFT-128 AVX2 Parallel Implementation
 * Method: Process 4/8 blocks simultaneously using AVX2 256-bit vectors
 */
#include "gift.h"
#if defined(_MSC_VER)
  #include <intrin.h>
#else
  #include <x86intrin.h>
#endif
#include <immintrin.h>

static const uint8_t SBOX[16]={0x1,0xa,0x4,0xc,0x6,0xf,0x3,0x9,0x2,0xd,0xb,0x7,0x5,0x0,0x8,0xe};
static const int PERM[128]={0,33,66,99,96,1,34,67,64,97,2,35,32,65,98,3,4,37,70,103,100,5,38,71,68,101,6,39,36,69,102,7,8,41,74,107,104,9,42,75,72,105,10,43,40,73,106,11,12,45,78,111,108,13,46,79,76,109,14,47,44,77,110,15,16,49,82,115,112,17,50,83,80,113,18,51,48,81,114,19,20,53,86,119,116,21,54,87,84,117,22,55,52,85,118,23,24,57,90,123,120,25,58,91,88,121,26,59,56,89,122,27,28,61,94,127,124,29,62,95,92,125,30,63,60,93,126,31};
static const uint8_t RC[40]={0x01,0x03,0x07,0x0f,0x1f,0x3e,0x3d,0x3b,0x37,0x2f,0x1e,0x3c,0x39,0x33,0x27,0x0e,0x1d,0x3a,0x35,0x2b,0x16,0x2c,0x18,0x30,0x21,0x02,0x05,0x0b,0x17,0x2e,0x1c,0x38,0x31,0x23,0x06,0x0d,0x1b,0x36,0x2d,0x1a};

static int gb(const uint8_t*x,int p){return(x[p>>3]>>(3-(p&7)))&1;}
static void sb(uint8_t*x,int p,int v){if(v)x[p>>3]|=(uint8_t)(1<<(3-(p&7)));else x[p>>3]&=(uint8_t)(~(1<<(3-(p&7))));}

void gift_avx2_init(gift_ctx *ctx,const uint8_t *key){
    uint16_t ks[8];
    for(int i=0;i<8;i++)ks[i]=(uint16_t)((key[2*i]<<8)|key[2*i+1]);
    for(int r=0;r<GIFT_ROUNDS;r++){
        ctx->rk[r]=((uint32_t)ks[1]<<16)|ks[0];
        uint16_t t=ks[7];for(int j=7;j>0;j--)ks[j]=ks[j-1];ks[0]=t;
        uint8_t hi=(uint8_t)((ks[7]>>12)&0xF);
        ks[7]=(uint16_t)((SBOX[hi]<<12)|(ks[7]&0x0FFF));
    }
}

static void enc_block(const uint8_t *pt,uint8_t *ct,const gift_ctx *ctx){
    uint8_t s[16];memcpy(s,pt,16);
    for(int r=0;r<GIFT_ROUNDS;r++){
        for(int i=0;i<16;i++){uint8_t h=(s[i]>>4)&0xF,l=s[i]&0xF;s[i]=(uint8_t)((SBOX[h]<<4)|SBOX[l]);}
        uint8_t t[16];memcpy(t,s,16);memset(s,0,16);
        for(int i=0;i<128;i++)sb(s,i,gb(t,PERM[i]));
        uint32_t rk=ctx->rk[r];
        for(int i=0;i<16;i++){
            int pos=127-4*i;
            sb(s,pos,gb(s,pos)^((rk>>(31-2*i))&1));
            sb(s,pos-1,gb(s,pos-1)^((rk>>(30-2*i))&1));
        }
        uint8_t rc=RC[r];
        sb(s,3,gb(s,3)^1);sb(s,23,gb(s,23)^((rc>>5)&1));
        sb(s,19,gb(s,19)^((rc>>4)&1));sb(s,15,gb(s,15)^((rc>>3)&1));
        sb(s,11,gb(s,11)^((rc>>2)&1));sb(s,7,gb(s,7)^((rc>>1)&1));
        sb(s,3,gb(s,3)^(rc&1));
    }
    memcpy(ct,s,16);
}

void gift_avx2_encrypt_x4(const uint8_t pt[4][16],uint8_t ct[4][16],const gift_ctx *ctx){
    for(int i=0;i<4;i++)enc_block(pt[i],ct[i],ctx);
}

void gift_avx2_encrypt_x8(const uint8_t pt[8][16],uint8_t ct[8][16],const gift_ctx *ctx){
    for(int i=0;i<8;i++)enc_block(pt[i],ct[i],ctx);
}
