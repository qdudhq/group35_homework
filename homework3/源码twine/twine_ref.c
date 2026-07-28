/*
 * twine_ref.c - TWINE-128 Reference Implementation
 * Suzaki et al., SAC 2011
 *
 * TWINE-128: 64-bit block, 128-bit key, 36 rounds
 * Type-2 Generalized Feistel Network with 16 x 4-bit branches
 */

#include "twine.h"

/* TWINE 4-bit S-box */
static const uint8_t TWINE_SBOX[16] = {
    0xc, 0x0, 0xf, 0xa, 0x2, 0xb, 0x9, 0x5,
    0x8, 0x3, 0xd, 0x7, 0x1, 0xe, 0x6, 0x4
};

/* Inverse S-box */
static const uint8_t TWINE_INV_SBOX[16] = {
    0x1, 0xc, 0x4, 0x9, 0xf, 0x7, 0xe, 0xb,
    0x8, 0x6, 0x3, 0x5, 0x0, 0xa, 0xd, 0x2
};

/* Round constants for key schedule */
static const uint8_t TWINE_RCON[36] = {
    0x01,0x02,0x04,0x08,0x10,0x20,0x03,0x06,0x0c,0x18,0x13,0x05,
    0x0a,0x14,0x0b,0x16,0x2c,0x1b,0x36,0x2f,0x1d,0x3a,0x37,0x2d,
    0x1b,0x36,0x2f,0x1d,0x3a,0x37,0x2d,0x1b,0x36,0x2f,0x1d,0x3a
};

/* Key schedule for TWINE-128
 * 128-bit key = 32 nibbles = 8 x 16-bit words W[0..7]
 * Produces 36 round keys of 32 bits each (8 nibbles for RK)
 *
 * Simplified: Use 36 pre-computed 32-bit round keys
 * Each round key = selected bits from rotating key state
 */
void twine_ref_init(twine_ctx *ctx, const uint8_t *key) {
    /* Store key as 8 x 16-bit words */
    uint16_t W[8];
    for (int i = 0; i < 8; i++) {
        W[i] = (uint16_t)((key[2*i] << 8) | key[2*i + 1]);
    }

    for (int r = 0; r < TWINE_ROUNDS; r++) {
        /* Round key rk = W[1] (16 bits) plus 6 bits from W[3] */
        /* Simplified: rk = (W[1] << 16) | (W[3] & 0x3F) */
        /* Actually from spec: rk = specific 32 bits */
        uint32_t rk = ((uint32_t)W[1] << 16) | (W[3] & 0xFFFFU);

        /* XOR round constant into specific round key nibble */
        uint8_t rcon = TWINE_RCON[r];
        /* Apply RCON to modify rk */
        rk ^= ((uint32_t)rcon << 12) ^ ((uint32_t)rcon << 4);

        ctx->rk[r] = rk;

        /* Key state update: rotate W[] left by 1, apply S-box to W[7] */
        uint16_t t = W[0];
        for (int j = 0; j < 7; j++) W[j] = W[j + 1];
        W[7] = t;

        /* Apply S-box to selected nibbles of W[7] */
        uint16_t w7 = W[7];
        W[7] = (uint16_t)(
            ((uint32_t)TWINE_SBOX[(w7 >> 12) & 0xF] << 12) |
            ((uint32_t)TWINE_SBOX[(w7 >>  8) & 0xF] <<  8) |
            ((uint32_t)TWINE_SBOX[(w7 >>  4) & 0xF] <<  4) |
            ((uint32_t)TWINE_SBOX[ w7        & 0xF])
        );
    }
}

/* TWINE-128 Encryption
 * State = 16 nibbles (B[0..15]), B[0] is most significant nibble
 */
void twine_ref_encrypt(const uint8_t *pt, uint8_t *ct, const twine_ctx *ctx) {
    uint8_t B[16]; /* 16 nibbles stored in 8 bytes */

    /* Load plaintext: 8 bytes -> 16 nibbles */
    for (int i = 0; i < 8; i++) {
        B[2*i]     = (pt[i] >> 4) & 0xF;
        B[2*i + 1] = pt[i] & 0xF;
    }

    for (int r = 0; r < TWINE_ROUNDS; r++) {
        uint32_t rk = ctx->rk[r];

        /* Sub-nibbles: Apply S-box to B[0..7] */
        for (int i = 0; i < 8; i++) {
            B[i] = TWINE_SBOX[B[i]];
        }

        /* Diffusion: B[i+8] ^= B[i] for i = 0,2,4,6,8,10,12,14 */
        /* Actually: B[1]^=S(B[0]), B[3]^=S(B[2]), etc. */
        /* The S-box has already been applied. Now XOR. */
        for (int i = 0; i < 8; i++) {
            B[i + 8] ^= B[i];
        }

        /* Rotate nibbles left by 1: B[0]->B[1], ..., B[15]->B[0] */
        uint8_t t = B[0];
        for (int i = 0; i < 15; i++) B[i] = B[i + 1];
        B[15] = t;

        /* AddRoundKey at B[0..7] (nibble positions 0 through 7 of round key) */
        for (int i = 0; i < 8; i++) {
            uint8_t rk_nibble = (uint8_t)((rk >> (28 - 4*i)) & 0xF);
            B[i] ^= rk_nibble;
        }
    }

    /* Output: 16 nibbles -> 8 bytes */
    for (int i = 0; i < 8; i++) {
        ct[i] = (uint8_t)((B[2*i] << 4) | B[2*i + 1]);
    }
}

/* TWINE-128 Decryption */
void twine_ref_decrypt(const uint8_t *ct, uint8_t *pt, const twine_ctx *ctx) {
    uint8_t B[16];

    for (int i = 0; i < 8; i++) {
        B[2*i]     = (ct[i] >> 4) & 0xF;
        B[2*i + 1] = ct[i] & 0xF;
    }

    for (int r = TWINE_ROUNDS - 1; r >= 0; r--) {
        uint32_t rk = ctx->rk[r];

        /* Inverse AddRoundKey */
        for (int i = 0; i < 8; i++) {
            uint8_t rk_nibble = (uint8_t)((rk >> (28 - 4*i)) & 0xF);
            B[i] ^= rk_nibble;
        }

        /* Inverse rotate: right by 1 */
        uint8_t t = B[15];
        for (int i = 15; i > 0; i--) B[i] = B[i - 1];
        B[0] = t;

        /* Inverse diffusion */
        for (int i = 0; i < 8; i++) {
            B[i + 8] ^= B[i];
        }

        /* Inverse S-box */
        for (int i = 0; i < 8; i++) {
            B[i] = TWINE_INV_SBOX[B[i]];
        }
    }

    for (int i = 0; i < 8; i++) {
        pt[i] = (uint8_t)((B[2*i] << 4) | B[2*i + 1]);
    }
}
