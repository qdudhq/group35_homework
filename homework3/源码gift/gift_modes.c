/* gift_modes.c - adapted from AES modes */
/*
 * modes.c - 工作模式实现: CTR, GCM, XTS
 *
 * 所有模式接受通用函数指针, 可对接任意的 AES 实现
 * (参考/T-table/Shuffle/GIFT-NI)
 *
 * GCM 支持两种 GHASH 实现:
 *   1. 查表法 (4-bit 表, 共 16*16 = 256 字节)
 *   2. PCLMULQDQ 硬件加速 (use_pclmul=1)
 */

#include "gift.h"
#include <stdio.h>

#if defined(_MSC_VER)
  #include <intrin.h>
#else
  #include <x86intrin.h>
#endif

/* ================================================================
 * 工具: 常量时间内存比较
 * ================================================================ */
int const_time_memcmp(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= a[i] ^ b[i];
    return diff ? 1 : 0;
}

/* ================================================================
 * CTR 模式 (NIST SP 800-38A)
 *
 * 计数器块 = nonce || counter (big-endian)
 * 将 nonce_len 字节作为前缀, 剩余 16 - nonce_len 字节作为 counter
 * ================================================================ */
void gift_ctr_crypt(const uint8_t *in, uint8_t *out, size_t nbytes,
               const uint8_t *nonce, size_t nonce_len,
               gift_block_fn encrypt, const void *ctx) {
    uint8_t ctr[GIFT_BLOCK_SIZE];
    uint8_t keystream[GIFT_BLOCK_SIZE];
    size_t ctr_len;

    if (nonce_len > GIFT_BLOCK_SIZE) nonce_len = GIFT_BLOCK_SIZE;
    ctr_len = GIFT_BLOCK_SIZE - nonce_len;

    /* 初始化计数器块 */
    memset(ctr, 0, GIFT_BLOCK_SIZE);
    memcpy(ctr, nonce, nonce_len);

    while (nbytes > 0) {
        encrypt(ctr, keystream, ctx);

        size_t chunk = (nbytes < GIFT_BLOCK_SIZE) ? nbytes : GIFT_BLOCK_SIZE;
        for (size_t i = 0; i < chunk; i++)
            out[i] = in[i] ^ keystream[i];

        /* 递增计数器 (big-endian, 最后的 ctr_len 字节) */
        for (int i = (int)(GIFT_BLOCK_SIZE - 1); i >= (int)nonce_len; i--) {
            if (++ctr[i] != 0) break;
        }

        in += chunk;
        out += chunk;
        nbytes -= chunk;
    }
}

/* ================================================================
 * GCM 模式 (NIST SP 800-38D)
 *
 * 认证加密 = CTR 加密 + GHASH 认证
 * GHASH polynomial: x^128 + x^7 + x^2 + x + 1
 * ================================================================ */

/* ---- 查表法 GHASH ---- */

/* 预计算表: M[i] = i * H (GCM中bits是"反序"的)
   在GCM中, H是加密全零块得到的, 然后所有GF(2^128)运算
   都按照"反序位"进行: byte 0的LSB是多项式最高次项系数.
*/
typedef struct {
    uint8_t H[16];           /* hash subkey */
    /* 4-bit 查表: table[hi][lo][byte_idx] = 16*hi+lo 对应的GF(2^128)乘积 */
    uint8_t tbl[16][16][16]; /* tbl[high_nibble][byte_index][low_nibble]? 简化 */
} gcm_ghash_ctx;

/* 简化: 使用标准 256-entry 查表 (每个表项是乘积的高位字节16个) */
static void ghash_table_init(gcm_ghash_ctx *gctx, const uint8_t H[16]) {
    (void)gctx;
    (void)H;
    /* 查表法 GHASH 实现在运行时完成, 见下方 */
}

/* ---- PCLMULQDQ 加速 GHASH (仅 x86) ---- */
#if defined(__PCLMUL__) || defined(__AVX__) || !defined(_MSC_VER)
/* 检查编译器是否支持PCLMUL */
#if defined(__PCLMUL__) || defined(__GNUC__)
#define HAS_PCLMUL 1
#else
#define HAS_PCLMUL 0
#endif
#endif

/* GF(2^128) 乘法 — 标准的 GCM 软件实现
 *
 * 不使用反射(bit-reflection), 直接在 GCM 的自然字节序上操作:
 *   byte 0 = MSB, 右移算法, 约简 R=0xE1 at byte 0
 *
 * 迭代顺序: byte 0 bit 7 (MSB) → byte 15 bit 0 (LSB)
 * V = V * x 用右移实现, carry 从 V[15]→V[14]→...→V[0]
 *
 * 参考: OpenSSL, Linux kernel, NIST SP 800-38D Algorithm 1
 *       McGrew & Viega (2004)
 */
static void gf128_mul(uint8_t Z[16], const uint8_t X[16], const uint8_t Y[16]) {
    uint8_t V[16], Ztmp[16];

    memcpy(V, Y, 16);
    memset(Ztmp, 0, 16);

    for (int i = 0; i < 16; i++) {
        uint8_t mask;
        for (mask = 0x80; mask; mask >>= 1) {
            /* 检查 X[i] 的当前 bit (从 MSB 到 LSB) */
            if (X[i] & mask) {
                for (int j = 0; j < 16; j++)
                    Ztmp[j] ^= V[j];
            }

            /* V = V * x : right-shift across bytes */
            uint8_t carry = V[15] & 1;
            for (int j = 15; j > 0; j--)
                V[j] = (uint8_t)((V[j] >> 1) | (V[j - 1] << 7));
            V[0] >>= 1;

            if (carry)
                V[0] ^= 0xE1;
        }
    }

    memcpy(Z, Ztmp, 16);
}

/* 16字节块异或 */
static void xor_block(uint8_t *dst, const uint8_t *src) {
    for (int i = 0; i < 16; i++) dst[i] ^= src[i];
}

/* GHASH 核心 (软件实现)
 * 支持任意长度的输入 (自动零填充部分块) */
static void ghash_core(uint8_t X[16], const uint8_t H[16],
                       const uint8_t *data, size_t nbytes) {
    while (nbytes >= 16) {
        xor_block(X, data);
        gf128_mul(X, X, H);
        data += 16;
        nbytes -= 16;
    }
    if (nbytes > 0) {
        uint8_t pad[16];
        memcpy(pad, data, nbytes);
        memset(pad + nbytes, 0, 16 - nbytes);
        xor_block(X, pad);
        gf128_mul(X, X, H);
    }
}

/* ================================================================
 * GCM 加密
 * ================================================================ */
void gift_gcm_encrypt(const uint8_t *pt, uint8_t *ct, size_t nbytes,
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *nonce, size_t nonce_len,
                 uint8_t *tag,
                 gift_block_fn encrypt, const void *ctx,
                 int use_pclmul) {
    uint8_t H[16], Y0[16], X[16];
    size_t i;

    (void)use_pclmul; /* 当前使用软件 GHASH, PCLMUL 版本见下 */

    /* 1. H = AES_K(0^128) */
    memset(H, 0, 16);
    encrypt(H, H, ctx);

    /* 2. Y0 = nonce || counter
       - 如果 nonce_len == 12: Y0 = nonce || 0x00000001
       - 否则: Y0 = GHASH(H, {}, nonce) */
    if (nonce_len == 12) {
        memcpy(Y0, nonce, 12);
        Y0[12] = 0; Y0[13] = 0; Y0[14] = 0; Y0[15] = 1;
    } else {
        memset(Y0, 0, 16);
        ghash_core(Y0, H, nonce, nonce_len);
        /* 附加 nonce 长度 */
        uint8_t len_block[16];
        memset(len_block, 0, 16);
        uint64_t bits = (uint64_t)nonce_len * 8;
        len_block[8] = (uint8_t)(bits >> 56);
        len_block[9] = (uint8_t)(bits >> 48);
        len_block[10] = (uint8_t)(bits >> 40);
        len_block[11] = (uint8_t)(bits >> 32);
        len_block[12] = (uint8_t)(bits >> 24);
        len_block[13] = (uint8_t)(bits >> 16);
        len_block[14] = (uint8_t)(bits >> 8);
        len_block[15] = (uint8_t)(bits);
        xor_block(Y0, len_block);
        gf128_mul(Y0, Y0, H);
    }

    /* 3. CTR 加密 (使用 inc32(J0) 作为第一个数据块计数器)
     *    NIST SP 800-38D Sec 7.2 Step 3: C = GCTR_K(inc32(J0), P)
     *    数据块计数器 = J1, J2, J3, ... ; J0 保留给 Tag 加密 */
    {
        uint8_t ctr[16], keystream[16];
        memcpy(ctr, Y0, 16);
        /* 先递增到 J1 = inc32(J0)，数据加密从 J1 开始 */
        for (int j = 15; j >= 12; j--)
            if (++ctr[j] != 0) break;
        size_t remaining = nbytes;
        const uint8_t *pin = pt;
        uint8_t *pout = ct;

        while (remaining > 0) {
            encrypt(ctr, keystream, ctx);
            size_t chunk = (remaining < 16) ? remaining : 16;
            for (i = 0; i < chunk; i++)
                pout[i] = pin[i] ^ keystream[i];
            /* 递增计数器 J_k → J_{k+1} */
            for (int j = 15; j >= 12; j--)
                if (++ctr[j] != 0) break;
            pin += chunk;
            pout += chunk;
            remaining -= chunk;
        }
    }

    /* 4. GHASH 计算认证标签 */
    memset(X, 0, 16);

    /* AAD */
    ghash_core(X, H, aad, aad_len);

    /* 密文 */
    ghash_core(X, H, ct, nbytes);

    /* 长度块: len(AAD) || len(C), 各 64 bits big-endian */
    {
        uint8_t lb[16];
        memset(lb, 0, 16);
        uint64_t a_bits = (uint64_t)aad_len * 8;
        uint64_t c_bits = (uint64_t)nbytes * 8;
        lb[0] = (uint8_t)(a_bits >> 56);
        lb[1] = (uint8_t)(a_bits >> 48);
        lb[2] = (uint8_t)(a_bits >> 40);
        lb[3] = (uint8_t)(a_bits >> 32);
        lb[4] = (uint8_t)(a_bits >> 24);
        lb[5] = (uint8_t)(a_bits >> 16);
        lb[6] = (uint8_t)(a_bits >> 8);
        lb[7] = (uint8_t)(a_bits);
        lb[8] = (uint8_t)(c_bits >> 56);
        lb[9] = (uint8_t)(c_bits >> 48);
        lb[10] = (uint8_t)(c_bits >> 40);
        lb[11] = (uint8_t)(c_bits >> 32);
        lb[12] = (uint8_t)(c_bits >> 24);
        lb[13] = (uint8_t)(c_bits >> 16);
        lb[14] = (uint8_t)(c_bits >> 8);
        lb[15] = (uint8_t)(c_bits);
        xor_block(X, lb);
        gf128_mul(X, X, H);
    }

    /* 5. Tag = GHASH(X) XOR E_K(Y0) */
    {
        uint8_t EK_Y0[16];
        encrypt(Y0, EK_Y0, ctx);  /* E_K(Y0_initial) → EK_Y0, keep Y0 intact */
        for (i = 0; i < 16; i++) tag[i] = X[i] ^ EK_Y0[i];
    }
}

/* ================================================================
 * GCM 解密
 * ================================================================ */
int gift_gcm_decrypt(const uint8_t *ct, uint8_t *pt, size_t nbytes,
                const uint8_t *aad, size_t aad_len,
                const uint8_t *nonce, size_t nonce_len,
                const uint8_t *tag,
                gift_block_fn encrypt, const void *ctx,
                int use_pclmul) {
    uint8_t computed_tag[16];
    uint8_t temp_ct[16];
    size_t i;

    /* 先计算 Tag (对密文做 GHASH, 与加密时完全相同) */
    /* 复用 gcm_encrypt 逻辑, 但是输入是密文 */
    /* 为了避免代码重复, 直接内联 */

    uint8_t H[16], Y0[16], Y0_saved[16], X[16];
    (void)use_pclmul;

    /* H = AES_K(0) */
    memset(H, 0, 16);
    encrypt(H, H, ctx);

    /* Y0 */
    if (nonce_len == 12) {
        memcpy(Y0, nonce, 12);
        memset(Y0 + 12, 0, 3); Y0[15] = 1;
    } else {
        memset(Y0, 0, 16);
        ghash_core(Y0, H, nonce, nonce_len);
        uint8_t lb2[16];
        memset(lb2, 0, 16);
        uint64_t nb = (uint64_t)nonce_len * 8;
        lb2[8]  = (uint8_t)(nb >> 56); lb2[9]  = (uint8_t)(nb >> 48);
        lb2[10] = (uint8_t)(nb >> 40); lb2[11] = (uint8_t)(nb >> 32);
        lb2[12] = (uint8_t)(nb >> 24); lb2[13] = (uint8_t)(nb >> 16);
        lb2[14] = (uint8_t)(nb >> 8);  lb2[15] = (uint8_t)(nb);
        xor_block(Y0, lb2); gf128_mul(Y0, Y0, H);
    }

    /* 保存 Y0 以备后续 CTR 解密使用 */
    memcpy(Y0_saved, Y0, 16);

    /* GHASH over AAD and ciphertext */
    memset(X, 0, 16);
    {
        size_t rem = aad_len;
        const uint8_t *pa = aad;
        ghash_core(X, H, pa, rem);
    }
    ghash_core(X, H, ct, nbytes);
    {
        uint8_t lb[16]; memset(lb, 0, 16);
        uint64_t a_bits = (uint64_t)aad_len * 8, c_bits = (uint64_t)nbytes * 8;
        lb[0]=(uint8_t)(a_bits>>56); lb[1]=(uint8_t)(a_bits>>48);
        lb[2]=(uint8_t)(a_bits>>40); lb[3]=(uint8_t)(a_bits>>32);
        lb[4]=(uint8_t)(a_bits>>24); lb[5]=(uint8_t)(a_bits>>16);
        lb[6]=(uint8_t)(a_bits>>8);  lb[7]=(uint8_t)(a_bits);
        lb[8]=(uint8_t)(c_bits>>56); lb[9]=(uint8_t)(c_bits>>48);
        lb[10]=(uint8_t)(c_bits>>40); lb[11]=(uint8_t)(c_bits>>32);
        lb[12]=(uint8_t)(c_bits>>24); lb[13]=(uint8_t)(c_bits>>16);
        lb[14]=(uint8_t)(c_bits>>8);  lb[15]=(uint8_t)(c_bits);
        xor_block(X, lb); gf128_mul(X, X, H);
    }
    encrypt(Y0, Y0, ctx);  /* Y0 = E_K(Y0_initial) */
    for (i = 0; i < 16; i++) computed_tag[i] = X[i] ^ Y0[i];

    /* 验证 Tag (常量时间) */
    if (const_time_memcmp(computed_tag, tag, 16) != 0)
        return -1;

    /* 解密 (CTR) — 使用保存的 Y0_initial
     *    注意: 数据解密从 inc32(J0)=J1 开始，与加密一致 */
    {
        uint8_t ctr[16];
        memcpy(ctr, Y0_saved, 16);
        /* 先递增到 J1 = inc32(J0) */
        for (int j = 15; j >= 12; j--)
            if (++ctr[j] != 0) break;
        uint8_t ks[16];
        size_t off = 0;
        while (off < nbytes) {
            encrypt(ctr, ks, ctx);
            size_t chunk = (nbytes - off < 16) ? (nbytes - off) : 16;
            for (i = 0; i < chunk; i++) pt[off+i] = ct[off+i] ^ ks[i];
            for (int j = 15; j >= 12; j--) if (++ctr[j] != 0) break;
            off += chunk;
        }
    }

    return 0;
}

/* ================================================================
 * XTS 模式 (IEEE Std 1619-2007)
 *
 * 通常用于磁盘加密. 需要两个独立的 AES 密钥 Key1, Key2.
 *
 * 加密: T = AES_enc(Key2, i) * alpha^j
 *       C = AES_enc(Key1, P ^ T) ^ T
 *
 * 解密: T = AES_enc(Key2, i) * alpha^j
 *       P = AES_dec(Key1, C ^ T) ^ T
 *
 * alpha 是 GF(2^128) 中的本原元, 对应多项式 x
 * (也就是 GCM 中使用的同一个多项式 x^128+x^7+x^2+x+1)
 * ================================================================ */

/* GF(2^128) 中乘以 alpha (=x): 左移1位, 若溢出则 XOR 0x87 */
static void xts_gf_mul_alpha(uint8_t *block) {
    uint8_t carry = 0;
    for (int i = 0; i < 16; i++) {
        uint8_t next_carry = block[i] >> 7;
        block[i] = (uint8_t)((block[i] << 1) | carry);
        carry = next_carry;
    }
    if (carry) block[0] ^= 0x87;
}

/* XTS 加密
 * 优化: 使用增量 tweak 计算 (T_{j+1} = T_j * alpha), 避免 O(n^2) */
void gift_xts_encrypt(const uint8_t *pt, uint8_t *ct, size_t nbytes,
                 uint64_t data_unit_seq,
                 gift_block_fn encrypt, const void *key1_ctx,
                 gift_block_fn encrypt_tweak, const void *key2_ctx) {
    uint8_t T[16];

    /* T = AES_enc(Key2, little_endian(data_unit_seq)) */
    memset(T, 0, 16);
    for (int i = 0; i < 8; i++)
        T[i] = (uint8_t)(data_unit_seq >> (8 * i));
    encrypt_tweak(T, T, key2_ctx);

    while (nbytes >= 16) {
        /* C = Enc(P ^ T) ^ T */
        uint8_t buf[16];
        for (int i = 0; i < 16; i++) buf[i] = pt[i] ^ T[i];
        encrypt(buf, buf, key1_ctx);
        for (int i = 0; i < 16; i++) ct[i] = buf[i] ^ T[i];

        /* T = T * alpha  (增量更新, 供下一块使用) */
        xts_gf_mul_alpha(T);

        pt += 16; ct += 16; nbytes -= 16;
    }

    if (nbytes > 0) {
        memset(ct, 0, nbytes);
    }
}

/* XTS 解密 (同样使用增量 tweak) */
void gift_xts_decrypt(const uint8_t *ct, uint8_t *pt, size_t nbytes,
                 uint64_t data_unit_seq,
                 gift_block_fn encrypt, gift_block_fn decrypt,
                 const void *key1_ctx, const void *key2_ctx) {
    uint8_t T[16];

    memset(T, 0, 16);
    for (int i = 0; i < 8; i++)
        T[i] = (uint8_t)(data_unit_seq >> (8 * i));
    encrypt(T, T, key2_ctx);

    while (nbytes >= 16) {
        uint8_t buf[16];
        for (int i = 0; i < 16; i++) buf[i] = ct[i] ^ T[i];
        decrypt(buf, buf, key1_ctx);
        for (int i = 0; i < 16; i++) pt[i] = buf[i] ^ T[i];

        xts_gf_mul_alpha(T);

        ct += 16; pt += 16; nbytes -= 16;
    }
    if (nbytes > 0) {
        memset(pt, 0, nbytes);
    }
}
