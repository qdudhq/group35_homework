/*
 * gift.h - Common header for GIFT-128 implementations
 * GIFT: A lightweight block cipher (Banik et al., CHES 2017)
 * GIFT-128: 128-bit block, 128-bit key, 40 rounds
 */

#ifndef GIFT_H
#define GIFT_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define GIFT_BLOCK_SIZE      16
#define GIFT_KEY_SIZE        16
#define GIFT_ROUNDS          40

typedef struct { uint32_t rk[40]; } gift_ctx;
typedef void (*gift_block_fn)(const uint8_t *in, uint8_t *out, const void *ctx);

void gift_ref_init(gift_ctx *ctx, const uint8_t *key);
void gift_ref_encrypt(const uint8_t *pt, uint8_t *ct, const gift_ctx *ctx);
void gift_ref_decrypt(const uint8_t *ct, uint8_t *pt, const gift_ctx *ctx);

void gift_ttable_init(gift_ctx *ctx, const uint8_t *key);
void gift_ttable_encrypt(const uint8_t *pt, uint8_t *ct, const gift_ctx *ctx);
void gift_ttable_decrypt(const uint8_t *ct, uint8_t *pt, const gift_ctx *ctx);

void gift_shuffle_init(gift_ctx *ctx, const uint8_t *key);
void gift_shuffle_encrypt(const uint8_t *pt, uint8_t *ct, const gift_ctx *ctx);
void gift_shuffle_encrypt_x4(const uint8_t pt[4][16], uint8_t ct[4][16], const gift_ctx *ctx);

void gift_bitslice_init(gift_ctx *ctx, const uint8_t *key);
void gift_bitslice_encrypt(const uint8_t *pt, uint8_t *ct, const gift_ctx *ctx);
void gift_bitslice_encrypt_x4(const uint8_t pt[4][16], uint8_t ct[4][16], const gift_ctx *ctx);

void gift_avx2_init(gift_ctx *ctx, const uint8_t *key);
void gift_avx2_encrypt_x4(const uint8_t pt[4][16], uint8_t ct[4][16], const gift_ctx *ctx);
void gift_avx2_encrypt_x8(const uint8_t pt[8][16], uint8_t ct[8][16], const gift_ctx *ctx);

void gift_ctr_crypt(const uint8_t *in, uint8_t *out, size_t nbytes,
    const uint8_t *nonce, size_t nonce_len, gift_block_fn enc, const void *ctx);
void gift_gcm_encrypt(const uint8_t *pt, uint8_t *ct, size_t nbytes,
    const uint8_t *aad, size_t aad_len, const uint8_t *nonce, size_t nonce_len,
    uint8_t *tag, gift_block_fn enc, const void *ctx);
int gift_gcm_decrypt(const uint8_t *ct, uint8_t *pt, size_t nbytes,
    const uint8_t *aad, size_t aad_len, const uint8_t *nonce, size_t nonce_len,
    const uint8_t *tag, gift_block_fn enc, const void *ctx);
void gift_xts_encrypt(const uint8_t *pt, uint8_t *ct, size_t nbytes, uint64_t seq,
    gift_block_fn enc, const void *k1, gift_block_fn enc_tweak, const void *k2);
void gift_xts_decrypt(const uint8_t *ct, uint8_t *pt, size_t nbytes, uint64_t seq,
    gift_block_fn enc, gift_block_fn dec, const void *k1, const void *k2);

double get_time_us(void);
void print_hex(const char *label, const uint8_t *data, size_t len);
int const_time_memcmp(const uint8_t *a, const uint8_t *b, size_t len);
int cpu_has_ssse3(void);
int cpu_has_avx(void);
int cpu_has_avx2(void);

#endif
