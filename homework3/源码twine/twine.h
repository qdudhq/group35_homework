/*
 * twine.h - TWINE-128 lightweight block cipher
 * Suzaki et al., SAC 2011
 * TWINE-128: 64-bit block, 128-bit key, 36 rounds
 * Type-2 Generalized Feistel Network (GFN)
 */

#ifndef TWINE_H
#define TWINE_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define TWINE_BLOCK_SIZE      8
#define TWINE_KEY_SIZE        16
#define TWINE_ROUNDS          36
#define TWINE_RK_WORDS        36

typedef struct { uint32_t rk[TWINE_RK_WORDS]; } twine_ctx;
typedef void (*twine_block_fn)(const uint8_t *in, uint8_t *out, const void *ctx);

void twine_ref_init(twine_ctx *ctx, const uint8_t *key);
void twine_ref_encrypt(const uint8_t *pt, uint8_t *ct, const twine_ctx *ctx);
void twine_ref_decrypt(const uint8_t *ct, uint8_t *pt, const twine_ctx *ctx);

void twine_ttable_init(twine_ctx *ctx, const uint8_t *key);
void twine_ttable_encrypt(const uint8_t *pt, uint8_t *ct, const twine_ctx *ctx);
void twine_ttable_decrypt(const uint8_t *ct, uint8_t *pt, const twine_ctx *ctx);

void twine_shuffle_init(twine_ctx *ctx, const uint8_t *key);
void twine_shuffle_encrypt(const uint8_t *pt, uint8_t *ct, const twine_ctx *ctx);
void twine_shuffle_encrypt_x4(const uint8_t pt[4][8], uint8_t ct[4][8], const twine_ctx *ctx);

void twine_bitslice_init(twine_ctx *ctx, const uint8_t *key);
void twine_bitslice_encrypt(const uint8_t *pt, uint8_t *ct, const twine_ctx *ctx);
void twine_bitslice_encrypt_x4(const uint8_t pt[4][8], uint8_t ct[4][8], const twine_ctx *ctx);

void twine_avx2_init(twine_ctx *ctx, const uint8_t *key);
void twine_avx2_encrypt_x4(const uint8_t pt[4][8], uint8_t ct[4][8], const twine_ctx *ctx);
void twine_avx2_encrypt_x8(const uint8_t pt[8][8], uint8_t ct[8][8], const twine_ctx *ctx);

void twine_ctr_crypt(const uint8_t *in, uint8_t *out, size_t nbytes,
    const uint8_t *nonce, size_t nonce_len, twine_block_fn enc, const void *ctx);
void twine_gcm_encrypt(const uint8_t *pt, uint8_t *ct, size_t nbytes,
    const uint8_t *aad, size_t aad_len, const uint8_t *nonce, size_t nonce_len,
    uint8_t *tag, twine_block_fn enc, const void *ctx);
int twine_gcm_decrypt(const uint8_t *ct, uint8_t *pt, size_t nbytes,
    const uint8_t *aad, size_t aad_len, const uint8_t *nonce, size_t nonce_len,
    const uint8_t *tag, twine_block_fn enc, const void *ctx);
void twine_xts_encrypt(const uint8_t *pt, uint8_t *ct, size_t nbytes, uint64_t seq,
    twine_block_fn enc, const void *k1, twine_block_fn enc_tweak, const void *k2);
void twine_xts_decrypt(const uint8_t *ct, uint8_t *pt, size_t nbytes, uint64_t seq,
    twine_block_fn enc, twine_block_fn dec, const void *k1, const void *k2);

double get_time_us(void);
void print_hex(const char *label, const uint8_t *data, size_t len);
int const_time_memcmp(const uint8_t *a, const uint8_t *b, size_t len);
int cpu_has_ssse3(void);
int cpu_has_avx(void);
int cpu_has_avx2(void);

#endif
