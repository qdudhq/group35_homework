/*
 * sm4.h - Common header for SM4 implementations and modes
 * 实验3: 对称密码算法的软件实现 (SM4 国密算法)
 *
 * 包含: 参考实现、T-table优化、Shuffle(SSSE3)优化、SM4-NI/AVX2优化
 * 工作模式: CTR, GCM, XTS
 */

#ifndef SM4_H
#define SM4_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * 常量和宏定义
 * ================================================================ */
#define SM4_BLOCK_SIZE        16
#define SM4_KEY_SIZE          16
#define SM4_ROUNDS            32
#define SM4_RK_WORDS          32

/* SM4 通用上下文 */
typedef struct {
    uint32_t rk[SM4_RK_WORDS];
} sm4_ctx;

/* SM4-NI 上下文 (16字节对齐) */
typedef struct {
    uint8_t  rk[SM4_RK_WORDS * 4];
} sm4_ni_ctx;

/* 函数指针类型 */
typedef void (*sm4_block_fn)(const uint8_t *in, uint8_t *out, const void *ctx);

/* ================================================================
 * 1. 参考实现 API
 * ================================================================ */
void sm4_ref_init(sm4_ctx *ctx, const uint8_t *key);
void sm4_ref_encrypt(const uint8_t *pt, uint8_t *ct, const sm4_ctx *ctx);
void sm4_ref_decrypt(const uint8_t *ct, uint8_t *pt, const sm4_ctx *ctx);

/* ================================================================
 * 2. T-table 优化实现 API
 * ================================================================ */
void sm4_ttable_init(sm4_ctx *ctx, const uint8_t *key);
void sm4_ttable_encrypt(const uint8_t *pt, uint8_t *ct, const sm4_ctx *ctx);
void sm4_ttable_decrypt(const uint8_t *ct, uint8_t *pt, const sm4_ctx *ctx);

/* ================================================================
 * 3. SSSE3 Shuffle 优化实现 API
 * ================================================================ */
void sm4_shuffle_init(sm4_ctx *ctx, const uint8_t *key);
void sm4_shuffle_encrypt(const uint8_t *pt, uint8_t *ct, const sm4_ctx *ctx);
void sm4_shuffle_encrypt_x4(const uint8_t pt[4][16], uint8_t ct[4][16],
                            const sm4_ctx *ctx);

/* ================================================================
 * 4. SM4-NI 指令集优化 API
 * ================================================================ */
int  sm4_ni_available(void);
void sm4_ni_init(sm4_ni_ctx *ctx, const uint8_t *key);
void sm4_ni_encrypt(const uint8_t *pt, uint8_t *ct, const sm4_ni_ctx *ctx);
void sm4_ni_decrypt(const uint8_t *ct, uint8_t *pt, const sm4_ni_ctx *ctx);

/* ================================================================
 * 5. AVX2 并行优化 API
 * ================================================================ */
void sm4_avx2_init(sm4_ctx *ctx, const uint8_t *key);
void sm4_avx2_encrypt_x4(const uint8_t pt[4][16], uint8_t ct[4][16],
                         const sm4_ctx *ctx);
void sm4_avx2_encrypt_x8(const uint8_t pt[8][16], uint8_t ct[8][16],
                         const sm4_ctx *ctx);

/* ================================================================
 * 6. 工作模式 API
 * ================================================================ */
/* CTR */
void sm4_ctr_crypt(const uint8_t *in, uint8_t *out, size_t nbytes,
                   const uint8_t *nonce, size_t nonce_len,
                   sm4_block_fn encrypt, const void *ctx);

/* GCM */
void sm4_gcm_encrypt(const uint8_t *pt, uint8_t *ct, size_t nbytes,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *nonce, size_t nonce_len,
                     uint8_t *tag,
                     sm4_block_fn encrypt, const void *ctx);
int  sm4_gcm_decrypt(const uint8_t *ct, uint8_t *pt, size_t nbytes,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *nonce, size_t nonce_len,
                     const uint8_t *tag,
                     sm4_block_fn encrypt, const void *ctx);

/* XTS */
void sm4_xts_encrypt(const uint8_t *pt, uint8_t *ct, size_t nbytes,
                     uint64_t data_unit_seq,
                     sm4_block_fn encrypt, const void *key1_ctx,
                     sm4_block_fn encrypt_tweak, const void *key2_ctx);
void sm4_xts_decrypt(const uint8_t *ct, uint8_t *pt, size_t nbytes,
                     uint64_t data_unit_seq,
                     sm4_block_fn encrypt, sm4_block_fn decrypt,
                     const void *key1_ctx, const void *key2_ctx);

/* ================================================================
 * 7. 工具函数
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

#ifdef __cplusplus
}
#endif

#endif /* SM4_H */
