/* gift_ttable.c - GIFT-128 T-table optimization */
#include "gift.h"
#include <string.h>

static const uint8_t SBOX[16]={0x1,0xa,0x4,0xc,0x6,0xf,0x3,0x9,0x2,0xd,0xb,0x7,0x5,0x0,0x8,0xe};
static const uint8_t INV_SBOX[16]={0xd,0x0,0x8,0x6,0x2,0xc,0x4,0xb,0xe,0x7,0x1,0xa,0x3,0x9,0xf,0x5};
static const int PERM[128]={0,33,66,99,96,1,34,67,64,97,2,35,32,65,98,3,4,37,70,103,100,5,38,71,68,101,6,39,36,69,102,7,8,41,74,107,104,9,42,75,72,105,10,43,40,73,106,11,12,45,78,111,108,13,46,79,76,109,14,47,44,77,110,15,16,49,82,115,112,17,50,83,80,113,18,51,48,81,114,19,20,53,86,119,116,21,54,87,84,117,22,55,52,85,118,23,24,57,90,123,120,25,58,91,88,121,26,59,56,89,122,27,28,61,94,127,124,29,62,95,92,125,30,63,60,93,126,31};
static const int INV_PERM[128]={0,5,10,15,16,21,26,31,32,37,42,47,48,53,58,63,64,69,74,79,80,85,90,95,96,101,106,111,112,117,122,127,12,1,6,11,28,17,22,27,44,33,38,43,60,49,54,59,76,65,70,75,92,81,86,91,108,97,102,107,124,113,118,123,8,13,2,7,24,29,18,23,40,45,34,39,56,61,50,55,72,77,66,71,88,93,82,87,104,109,98,103,120,125,114,119,4,9,14,3,20,25,30,19,36,41,46,35,52,57,62,51,68,73,78,67,84,89,94,83,100,105,110,99,116,121,126,115};
static const uint8_t RC[40]={0x01,0x03,0x07,0x0f,0x1f,0x3e,0x3d,0x3b,0x37,0x2f,0x1e,0x3c,0x39,0x33,0x27,0x0e,0x1d,0x3a,0x35,0x2b,0x16,0x2c,0x18,0x30,0x21,0x02,0x05,0x0b,0x17,0x2e,0x1c,0x38,0x31,0x23,0x06,0x0d,0x1b,0x36,0x2d,0x1a};

static int gb(const uint8_t*x,int p){return (x[p>>3]>>(3-(p&7)))&1;}
static void sb(uint8_t*x,int p,int v){if(v)x[p>>3]|=(uint8_t)(1<<(3-(p&7)));else x[p>>3]&=(uint8_t)(~(1<<(3-(p&7))));}

/* Precomputed T-tables: T_ENC[pos][val][byte] = contribution for nibble pos with value val */
static uint8_t T_ENC[32][16][16];
static uint8_t T_DEC[32][16][16];
static int tables_ok=0;

static void build_tables(void){
    for(int pos=0;pos<32;pos++){
        for(int n=0;n<16;n++){
            uint8_t x[16]={0};int bi=pos>>1;
            if(pos&1)x[bi]=(uint8_t)(x[bi]|n);
            else x[bi]=(uint8_t)(x[bi]|(n<<4));
            /* SubCells */
            for(int i=0;i<16;i++){uint8_t h=(x[i]>>4)&0xF,l=x[i]&0xF;x[i]=(uint8_t)((SBOX[h]<<4)|SBOX[l]);}
            /* PermBits */
            uint8_t p[16];memcpy(p,x,16);memset(x,0,16);
            for(int i=0;i<128;i++)sb(x,i,gb(p,PERM[i]));
            memcpy(T_ENC[pos][n],x,16);
            /* Dec */
            uint8_t d[16]={0};
            if(pos&1)d[bi]=(uint8_t)(d[bi]|n);
            else d[bi]=(uint8_t)(d[bi]|(n<<4));
            /* InvPermBits+InvSubCells */
            uint8_t dp[16];memcpy(dp,d,16);memset(d,0,16);
            for(int i=0;i<128;i++)sb(d,i,gb(dp,INV_PERM[i]));
            for(int i=0;i<16;i++){uint8_t h=(d[i]>>4)&0xF,l=d[i]&0xF;d[i]=(uint8_t)((INV_SBOX[h]<<4)|INV_SBOX[l]);}
            memcpy(T_DEC[pos][n],d,16);
        }
    }
    tables_ok=1;
}

void gift_ttable_init(gift_ctx *ctx,const uint8_t *key){
    if(!tables_ok)build_tables();
    uint16_t ks[8];
    for(int i=0;i<8;i++)ks[i]=(uint16_t)((key[2*i]<<8)|key[2*i+1]);
    for(int r=0;r<GIFT_ROUNDS;r++){
        ctx->rk[r]=((uint32_t)ks[1]<<16)|ks[0];
        uint16_t t=ks[7];for(int j=7;j>0;j--)ks[j]=ks[j-1];ks[0]=t;
        uint8_t hi=(uint8_t)((ks[7]>>12)&0xF);
        ks[7]=(uint16_t)((SBOX[hi]<<12)|(ks[7]&0x0FFF));
    }
}

void gift_ttable_encrypt(const uint8_t *pt,uint8_t *ct,const gift_ctx *ctx){
    uint8_t state[16];memcpy(state,pt,16);
    for(int r=0;r<GIFT_ROUNDS;r++){
        uint8_t next[16]={0};
        for(int pos=0;pos<32;pos++){
            int bi=pos>>1;uint8_t n;
            if(pos&1)n=state[bi]&0xF;
            else n=(state[bi]>>4)&0xF;
            for(int j=0;j<16;j++)next[j]^=T_ENC[pos][n][j];
        }
        memcpy(state,next,16);
        uint32_t rk=ctx->rk[r];
        for(int i=0;i<16;i++){
            int pos=127-4*i;
            sb(state,pos,gb(state,pos)^((rk>>(31-2*i))&1));
            sb(state,pos-1,gb(state,pos-1)^((rk>>(30-2*i))&1));
        }
        uint8_t rc=RC[r];
        sb(state,3,gb(state,3)^1);sb(state,23,gb(state,23)^((rc>>5)&1));
        sb(state,19,gb(state,19)^((rc>>4)&1));sb(state,15,gb(state,15)^((rc>>3)&1));
        sb(state,11,gb(state,11)^((rc>>2)&1));sb(state,7,gb(state,7)^((rc>>1)&1));
        sb(state,3,gb(state,3)^(rc&1));
    }
    memcpy(ct,state,16);
}

void gift_ttable_decrypt(const uint8_t *ct,uint8_t *pt,const gift_ctx *ctx){
    uint8_t state[16];memcpy(state,ct,16);
    for(int r=GIFT_ROUNDS-1;r>=0;r--){
        uint8_t rc=RC[r];
        sb(state,3,gb(state,3)^1);sb(state,23,gb(state,23)^((rc>>5)&1));
        sb(state,19,gb(state,19)^((rc>>4)&1));sb(state,15,gb(state,15)^((rc>>3)&1));
        sb(state,11,gb(state,11)^((rc>>2)&1));sb(state,7,gb(state,7)^((rc>>1)&1));
        sb(state,3,gb(state,3)^(rc&1));
        uint32_t rk=ctx->rk[r];
        for(int i=0;i<16;i++){
            int pos=127-4*i;
            sb(state,pos,gb(state,pos)^((rk>>(31-2*i))&1));
            sb(state,pos-1,gb(state,pos-1)^((rk>>(30-2*i))&1));
        }
        uint8_t next[16]={0};
        for(int pos=0;pos<32;pos++){
            int bi=pos>>1;uint8_t n;
            if(pos&1)n=state[bi]&0xF;
            else n=(state[bi]>>4)&0xF;
            for(int j=0;j<16;j++)next[j]^=T_DEC[pos][n][j];
        }
        memcpy(state,next,16);
    }
    memcpy(pt,state,16);
}
