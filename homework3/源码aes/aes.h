/*
 * aes.h - Common header for AES implementations and modes
 * 实验3: 对称密码算法的软件实现
 *
 * 包含: 参考实现、T-table优化、Shuffle(SSSE3)优化、AES-NI优化
 * 工作模式: CTR, GCM, XTS
 */

#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * 常量和宏定义
 * ================================================================ */
#define AES_BLOCK_SIZE       16
#define AES128_KEY_SIZE      16
#define AES192_KEY_SIZE      24
#define AES256_KEY_SIZE      32
#define AES128_ROUNDS        10
#define AES192_ROUNDS        12
#define AES256_ROUNDS        14
#define AES_MAX_ROUNDS       14
#define AES_MAX_RK_WORDS     60

/* AES 通用上下文 */
typedef struct {
    uint32_t rk[AES_MAX_RK_WORDS];
    int      nr;
} aes_ctx;

/* AES-NI 上下文 (16字节对齐) */
typedef struct {
    uint8_t  rk[AES_MAX_RK_WORDS * 4];
    int      nr;
} aes_ni_ctx;

/* 函数指针类型 */
typedef void (*aes_block_fn)(const uint8_t *in, uint8_t *out, const void *ctx);

/* ================================================================
 * 1. 参考实现 API
 * ================================================================ */
void aes_ref_init(aes_ctx *ctx, const uint8_t *key, int key_len);
void aes_ref_encrypt(const uint8_t *pt, uint8_t *ct, const aes_ctx *ctx);
void aes_ref_decrypt(const uint8_t *ct, uint8_t *pt, const aes_ctx *ctx);

/* ================================================================
 * 2. T-table 优化实现 API
 * ================================================================ */
void aes_ttable_init(aes_ctx *ctx, const uint8_t *key, int key_len);
void aes_ttable_encrypt(const uint8_t *pt, uint8_t *ct, const aes_ctx *ctx);
void aes_ttable_decrypt(const uint8_t *ct, uint8_t *pt, const aes_ctx *ctx);
const uint32_t* aes_ttable_get_Te(void);
const uint32_t* aes_ttable_get_Td(void);

/* ================================================================
 * 3. SSSE3 Shuffle 优化实现 API
 * ================================================================ */
void aes_shuffle_init(aes_ctx *ctx, const uint8_t *key, int key_len);
void aes_shuffle_encrypt(const uint8_t *pt, uint8_t *ct, const aes_ctx *ctx);
void aes_shuffle_encrypt_x4(const uint8_t pt[4][16], uint8_t ct[4][16],
                            const aes_ctx *ctx);
void aes_shuffle_encrypt_x8(const uint8_t pt[8][16], uint8_t ct[8][16],
                            const aes_ctx *ctx);

/* ================================================================
 * 4. AES-NI 优化实现 API
 * ================================================================ */
void aes_ni_init(aes_ni_ctx *ctx, const uint8_t *key, int key_len);
void aes_ni_encrypt(const uint8_t *pt, uint8_t *ct, const aes_ni_ctx *ctx);
void aes_ni_decrypt(const uint8_t *ct, uint8_t *pt, const aes_ni_ctx *ctx);
void aes_ni_encrypt_x4(const uint8_t pt[4][16], uint8_t ct[4][16],
                       const aes_ni_ctx *ctx);
void aes_ni_encrypt_x8(const uint8_t pt[8][16], uint8_t ct[8][16],
                       const aes_ni_ctx *ctx);

/* ================================================================
 * 5. 工作模式 API
 * ================================================================ */
/* CTR */
void ctr_crypt(const uint8_t *in, uint8_t *out, size_t nbytes,
               const uint8_t *nonce, size_t nonce_len,
               aes_block_fn encrypt, const void *ctx);

/* GCM */
void gcm_encrypt(const uint8_t *pt, uint8_t *ct, size_t nbytes,
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *nonce, size_t nonce_len,
                 uint8_t *tag,
                 aes_block_fn encrypt, const void *ctx,
                 int use_pclmul);
int  gcm_decrypt(const uint8_t *ct, uint8_t *pt, size_t nbytes,
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *nonce, size_t nonce_len,
                 const uint8_t *tag,
                 aes_block_fn encrypt, const void *ctx,
                 int use_pclmul);

/* XTS */
void xts_encrypt(const uint8_t *pt, uint8_t *ct, size_t nbytes,
                 uint64_t data_unit_seq,
                 aes_block_fn encrypt, const void *key1_ctx,
                 aes_block_fn encrypt_tweak, const void *key2_ctx);
void xts_decrypt(const uint8_t *ct, uint8_t *pt, size_t nbytes,
                 uint64_t data_unit_seq,
                 aes_block_fn encrypt, aes_block_fn decrypt,
                 const void *key1_ctx, const void *key2_ctx);

/* ================================================================
 * 6. 工具函数
 * ================================================================ */
double get_time_us(void);
void   print_hex(const char *label, const uint8_t *data, size_t len);
int    const_time_memcmp(const uint8_t *a, const uint8_t *b, size_t len);

/* CPU特性检测 */
int cpu_has_aesni(void);
int cpu_has_pclmul(void);
int cpu_has_ssse3(void);
int cpu_has_avx(void);
int cpu_has_avx2(void);
int cpu_has_vaes(void);
int cpu_has_gfni(void);

#ifdef __cplusplus
}
#endif

#endif /* AES_H */
