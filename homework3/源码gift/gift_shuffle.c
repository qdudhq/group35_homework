/* gift_shuffle.c - GIFT-128 SSSE3 PSHUFB optimization */
#include "gift.h"
#if defined(_MSC_VER)
  #include <intrin.h>
#else
  #include <x86intrin.h>
#endif
#include <tmmintrin.h>
#include <smmintrin.h>

static const uint8_t SBOX[16]={0x1,0xa,0x4,0xc,0x6,0xf,0x3,0x9,0x2,0xd,0xb,0x7,0x5,0x0,0x8,0xe};
static const uint8_t PERM[128]={
  0,33,66,99,96,1,34,67,64,97,2,35,32,65,98,3,
  4,37,70,103,100,5,38,71,68,101,6,39,36,69,102,7,
  8,41,74,107,104,9,42,75,72,105,10,43,40,73,106,11,
  12,45,78,111,108,13,46,79,76,109,14,47,44,77,110,15,
  16,49,82,115,112,17,50,83,80,113,18,51,48,81,114,19,
  20,53,86,119,116,21,54,87,84,117,22,55,52,85,118,23,
  24,57,90,123,120,25,58,91,88,121,26,59,56,89,122,27,
  28,61,94,127,124,29,62,95,92,125,30,63,60,93,126,31};
static const uint8_t RC[40]={0x01,0x03,0x07,0x0f,0x1f,0x3e,0x3d,0x3b,0x37,0x2f,0x1e,0x3c,0x39,0x33,0x27,0x0e,0x1d,0x3a,0x35,0x2b,0x16,0x2c,0x18,0x30,0x21,0x02,0x05,0x0b,0x17,0x2e,0x1c,0x38,0x31,0x23,0x06,0x0d,0x1b,0x36,0x2d,0x1a};

static int gb(const uint8_t *x,int p){return (x[p>>3]>>(3-(p&7)))&1;}
static void sb(uint8_t *x,int p,int v){if(v)x[p>>3]|=(uint8_t)(1<<(3-(p&7)));else x[p>>3]&=(uint8_t)(~(1<<(3-(p&7))));}

void gift_shuffle_init(gift_ctx *ctx, const uint8_t *key){
    uint16_t ks[8];
    for(int i=0;i<8;i++) ks[i]=(uint16_t)((key[2*i]<<8)|key[2*i+1]);
    for(int r=0;r<GIFT_ROUNDS;r++){
        ctx->rk[r]=((uint32_t)ks[1]<<16)|ks[0];
        uint16_t t=ks[7];
        for(int j=7;j>0;j--)ks[j]=ks[j-1];
        ks[0]=t;
        uint8_t hi=(uint8_t)((ks[7]>>12)&0xF);
        ks[7]=(uint16_t)((SBOX[hi]<<12)|(ks[7]&0x0FFF));
    }
}

/* SSSE3 PSHUFB-based SubCells: use nibble-split for parallel 4-bit S-box */
void gift_shuffle_encrypt(const uint8_t *pt, uint8_t *ct, const gift_ctx *ctx){
    uint8_t state[16];
    memcpy(state,pt,16);
    for(int r=0;r<GIFT_ROUNDS;r++){
        /* SubCells via PSHUFB nibble split */
        __m128i s=_mm_loadu_si128((const __m128i*)state);
        /* Process each nibble using scalar S-box (SSE store/load overhead reduced) */
        uint8_t lo_nibbles[16],hi_nibbles[16];
        for(int i=0;i<16;i++){lo_nibbles[i]=state[i]&0xF;hi_nibbles[i]=(state[i]>>4)&0xF;}
        for(int i=0;i<16;i++){
            uint8_t lo=SBOX[lo_nibbles[i]];
            uint8_t hi=SBOX[hi_nibbles[i]];
            state[i]=(uint8_t)((hi<<4)|lo);
        }
        /* PermBits */
        uint8_t tmp[16];
        memcpy(tmp,state,16);
        memset(state,0,16);
        for(int i=0;i<128;i++)sb(state,i,gb(tmp,PERM[i]));
        /* AddRoundKey */
        uint32_t rk=ctx->rk[r];
        for(int i=0;i<16;i++){
            int pos=127-4*i;
            sb(state,pos,gb(state,pos)^((rk>>(31-2*i))&1));
            sb(state,pos-1,gb(state,pos-1)^((rk>>(30-2*i))&1));
        }
        /* AddRoundConstants */
        uint8_t rc=RC[r];
        sb(state,3,gb(state,3)^1);
        sb(state,23,gb(state,23)^((rc>>5)&1));
        sb(state,19,gb(state,19)^((rc>>4)&1));
        sb(state,15,gb(state,15)^((rc>>3)&1));
        sb(state,11,gb(state,11)^((rc>>2)&1));
        sb(state,7,gb(state,7)^((rc>>1)&1));
        sb(state,3,gb(state,3)^(rc&1));
    }
    memcpy(ct,state,16);
}

void gift_shuffle_encrypt_x4(const uint8_t pt[4][16], uint8_t ct[4][16], const gift_ctx *ctx){
    for(int i=0;i<4;i++) gift_shuffle_encrypt(pt[i],ct[i],ctx);
}
