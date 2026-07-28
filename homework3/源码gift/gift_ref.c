/*
 * gift_ref.c - GIFT-128 reference implementation
 * Banik et al., CHES 2017
 *
 * GIFT-128: 128-bit block, 128-bit key, 40 rounds
 * SPN structure: SubCells -> PermBits -> AddRoundKey -> AddRoundConstants
 */

#include "gift.h"

/* 4-bit S-box: S[x] = value */
static const uint8_t GIFT_SBOX[16] = {
    0x1, 0xa, 0x4, 0xc, 0x6, 0xf, 0x3, 0x9,
    0x2, 0xd, 0xb, 0x7, 0x5, 0x0, 0x8, 0xe
};

/* Inverse S-box */
static const uint8_t GIFT_INV_SBOX[16] = {
    0xd, 0x0, 0x8, 0x6, 0x2, 0xc, 0x4, 0xb,
    0xe, 0x7, 0x1, 0xa, 0x3, 0x9, 0xf, 0x5
};

/* Bit permutation for GIFT-128
 * P maps new position -> old position
 * P[i] = j means bit i of output comes from bit j of input
 */
static const int GIFT_PERM[128] = {
      0,  33,  66,  99,  96,   1,  34,  67,
     64,  97,   2,  35,  32,  65,  98,   3,
      4,  37,  70, 103, 100,   5,  38,  71,
     68, 101,   6,  39,  36,  69, 102,   7,
      8,  41,  74, 107, 104,   9,  42,  75,
     72, 105,  10,  43,  40,  73, 106,  11,
     12,  45,  78, 111, 108,  13,  46,  79,
     76, 109,  14,  47,  44,  77, 110,  15,
     16,  49,  82, 115, 112,  17,  50,  83,
     80, 113,  18,  51,  48,  81, 114,  19,
     20,  53,  86, 119, 116,  21,  54,  87,
     84, 117,  22,  55,  52,  85, 118,  23,
     24,  57,  90, 123, 120,  25,  58,  91,
     88, 121,  26,  59,  56,  89, 122,  27,
     28,  61,  94, 127, 124,  29,  62,  95,
     92, 125,  30,  63,  60,  93, 126,  31
};

/* Inverse permutation: new_pos -> old_pos for decryption */
static const int GIFT_INV_PERM[128] = {
      0,   5,  10,  15,  16,  21,  26,  31,
     32,  37,  42,  47,  48,  53,  58,  63,
     64,  69,  74,  79,  80,  85,  90,  95,
     96, 101, 106, 111, 112, 117, 122, 127,
     12,   1,   6,  11,  28,  17,  22,  27,
     44,  33,  38,  43,  60,  49,  54,  59,
     76,  65,  70,  75,  92,  81,  86,  91,
    108,  97, 102, 107, 124, 113, 118, 123,
      8,  13,   2,   7,  24,  29,  18,  23,
     40,  45,  34,  39,  56,  61,  50,  55,
     72,  77,  66,  71,  88,  93,  82,  87,
    104, 109,  98, 103, 120, 125, 114, 119,
      4,   9,  14,   3,  20,  25,  30,  19,
     36,  41,  46,  35,  52,  57,  62,  51,
     68,  73,  78,  67,  84,  89,  94,  83,
    100, 105, 110,  99, 116, 121, 126, 115
};

/* Round constants: 6-bit values concatenated with 1-bit "1" */
static const uint8_t GIFT_RC[40] = {
    0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3e, 0x3d, 0x3b,
    0x37, 0x2f, 0x1e, 0x3c, 0x39, 0x33, 0x27, 0x0e,
    0x1d, 0x3a, 0x35, 0x2b, 0x16, 0x2c, 0x18, 0x30,
    0x21, 0x02, 0x05, 0x0b, 0x17, 0x2e, 0x1c, 0x38,
    0x31, 0x23, 0x06, 0x0d, 0x1b, 0x36, 0x2d, 0x1a
};

/* Get bit b from byte array (b=0 is MSB of byte 0) */
static int get_bit(const uint8_t *x, int pos) {
    return (x[pos >> 3] >> (3 - (pos & 7))) & 1;
}

/* Set bit b in byte array (b=0 is MSB of byte 0) */
static void set_bit(uint8_t *x, int pos, int val) {
    if (val)
        x[pos >> 3] |=  (uint8_t)(1 << (3 - (pos & 7)));
    else
        x[pos >> 3] &= (uint8_t)(~(1 << (3 - (pos & 7))));
}

/* SubCells: Apply 4-bit S-box to each nibble */
static void sub_cells(uint8_t state[16], const uint8_t *sbox) {
    for (int i = 0; i < 16; i++) {
        uint8_t hi = (state[i] >> 4) & 0xF;
        uint8_t lo = state[i] & 0xF;
        state[i] = (uint8_t)((sbox[hi] << 4) | sbox[lo]);
    }
}

/* PermBits: Apply bit permutation */
static void perm_bits(uint8_t state[16], const int *perm) {
    uint8_t tmp[16];
    memcpy(tmp, state, 16);
    memset(state, 0, 16);
    for (int i = 0; i < 128; i++) {
        set_bit(state, i, get_bit(tmp, perm[i]));
    }
}

/* Key schedule for GIFT-128
 * Key state = 8 x 16-bit words = 128 bits
 * Round key = k1||k0 (bits 127..112 and 111..96)
 * Update: rotate right by 16 bits, then S-box on new top word
 */
void gift_ref_init(gift_ctx *ctx, const uint8_t *key) {
    uint16_t ks[8]; /* 8 x 16-bit key words */

    /* Load key as 8 big-endian 16-bit words */
    for (int i = 0; i < 8; i++) {
        ks[i] = (uint16_t)((key[2*i] << 8) | key[2*i + 1]);
    }

    for (int r = 0; r < GIFT_ROUNDS; r++) {
        /* Round key = ks[0] || ks[1] (two 16-bit words = 32 bits) */
        ctx->rk[r] = ((uint32_t)ks[1] << 16) | ks[0];

        /* Key update: rotate right by 16 bits -> {ks[7], ks[0..6]} -> {old_ks[6], old_ks[7], old_ks[0..5]} */
        uint16_t t = ks[7];
        for (int j = 7; j > 0; j--)
            ks[j] = ks[j - 1];
        ks[0] = t;

        /* Apply S-box to most significant nibble of ks[7] */
        uint8_t hi = (uint8_t)((ks[7] >> 12) & 0xFU);
        uint8_t new_hi = GIFT_SBOX[hi];
        ks[7] = (uint16_t)((new_hi << 12) | (ks[7] & 0x0FFFU));
    }
}

/* GIFT-128 Encryption */
void gift_ref_encrypt(const uint8_t *pt, uint8_t *ct, const gift_ctx *ctx) {
    uint8_t state[16];
    memcpy(state, pt, 16);

    for (int r = 0; r < GIFT_ROUNDS; r++) {
        /* SubCells */
        sub_cells(state, GIFT_SBOX);

        /* PermBits */
        perm_bits(state, GIFT_PERM);

        /* AddRoundKey: XOR rk bits at positions 127,126, 123,122, 119,118, ... */
        uint32_t rk = ctx->rk[r];
        for (int i = 0; i < 16; i++) {
            int pos = 127 - 4*i;  /* bits 127, 123, 119, ... */
            int b0 = (rk >> (31 - 2*i)) & 1;
            int b1 = (rk >> (30 - 2*i)) & 1;
            set_bit(state, pos,     get_bit(state, pos)     ^ b0);
            set_bit(state, pos - 1, get_bit(state, pos - 1) ^ b1);
        }

        /* AddRoundConstants */
        uint8_t rc = GIFT_RC[r];
        /* Single bit "1" at position 3 */
        set_bit(state, 3, get_bit(state, 3) ^ 1);
        /* 6-bit constant at positions 23, 19, 15, 11, 7, 3 */
        set_bit(state, 23, get_bit(state, 23) ^ ((rc >> 5) & 1));
        set_bit(state, 19, get_bit(state, 19) ^ ((rc >> 4) & 1));
        set_bit(state, 15, get_bit(state, 15) ^ ((rc >> 3) & 1));
        set_bit(state, 11, get_bit(state, 11) ^ ((rc >> 2) & 1));
        set_bit(state,  7, get_bit(state,  7) ^ ((rc >> 1) & 1));
        set_bit(state,  3, get_bit(state,  3) ^ (rc & 1));
    }

    memcpy(ct, state, 16);
}

/* GIFT-128 Decryption */
void gift_ref_decrypt(const uint8_t *ct, uint8_t *pt, const gift_ctx *ctx) {
    uint8_t state[16];
    memcpy(state, ct, 16);

    for (int r = GIFT_ROUNDS - 1; r >= 0; r--) {
        /* AddRoundConstants (inverse) */
        uint8_t rc = GIFT_RC[r];
        set_bit(state, 23, get_bit(state, 23) ^ ((rc >> 5) & 1));
        set_bit(state, 19, get_bit(state, 19) ^ ((rc >> 4) & 1));
        set_bit(state, 15, get_bit(state, 15) ^ ((rc >> 3) & 1));
        set_bit(state, 11, get_bit(state, 11) ^ ((rc >> 2) & 1));
        set_bit(state,  7, get_bit(state,  7) ^ ((rc >> 1) & 1));
        set_bit(state,  3, get_bit(state,  3) ^ (rc & 1));
        set_bit(state,  3, get_bit(state,  3) ^ 1);

        /* AddRoundKey (inverse = same, XOR) */
        uint32_t rk = ctx->rk[r];
        for (int i = 0; i < 16; i++) {
            int pos = 127 - 4*i;
            int b0 = (rk >> (31 - 2*i)) & 1;
            int b1 = (rk >> (30 - 2*i)) & 1;
            set_bit(state, pos,     get_bit(state, pos)     ^ b0);
            set_bit(state, pos - 1, get_bit(state, pos - 1) ^ b1);
        }

        /* PermBits inverse */
        perm_bits(state, GIFT_INV_PERM);

        /* SubCells inverse */
        sub_cells(state, GIFT_INV_SBOX);
    }

    memcpy(pt, state, 16);
}
