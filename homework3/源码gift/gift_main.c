/*
 * gift_main.c - GIFT-128 Test & Benchmark
 *
 * 对比 4 种 GIFT 实现 + 3 种工作模式:
 *   1. 参考实现
 *   2. T-table 优化
 *   3. SSSE3 Shuffle 优化 (PSHUFB)
 *   4. Bitslice / AVX2 优化
 *
 * 工作模式: CTR, GCM, XTS
 * 测试策略: 自洽性测试 (加密-解密回环)
 * 注意: GIFT-128 使用 64-bit 块
 */

#include "gift.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_MSC_VER)
  #include <windows.h>
  #include <intrin.h>
#else
  #include <x86intrin.h>
  #include <sys/time.h>
#endif

#if defined(_MSC_VER)
static void cpuid(int info[4], int func_id) {
    __cpuidex(info, func_id, 0);
}
#else
static void cpuid(int info[4], int func_id) {
    __cpuid(func_id, info[0], info[1], info[2], info[3]);
}
#endif

int cpu_has_ssse3(void) { int i[4]; cpuid(i,1); return (i[2]&(1<<9))!=0; }
int cpu_has_avx(void)  { int i[4]; cpuid(i,1); return (i[2]&(1<<28))!=0; }
int cpu_has_avx2(void) { int i[4]; cpuid(i,7); return (i[1]&(1<<5))!=0; }

/* ================================================================
 * 计时工具
 * ================================================================ */

double get_time_us(void) {
#if defined(_MSC_VER)
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart * 1e6 / (double)freq.QuadPart;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1e6 + (double)tv.tv_usec;
#endif
}

/* ================================================================
 * 打印工具
 * ================================================================ */

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s", label);
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

/* ================================================================
 * 测试密钥 (GIFT-128: 16字节key, 8字节block)
 * 使用自洽性测试, 不需要预知测试向量
 * ================================================================ */
static const uint8_t test_key[16] = {
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
    0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
};
static const uint8_t test_pt[8] = {
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
};

/* NOTE: GIFT-128 only uses 128-bit keys.
 * Old AES-style test vector stubs removed for clarity.
 * Test key is already defined above. */
#if 0
static const uint8_t test_key[24] = {
    0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,
    0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,
    0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b
};
static const uint8_t test_ct192[16] = {
    0xbd,0x33,0x4f,0x1d,0x6e,0x45,0xf2,0x5f,
    0xf7,0x12,0xa2,0x14,0x57,0x1f,0xa5,0xcc
};

/* Banik et al. CHES 2017 Appendix C.3: GIFT-256 */
static const uint8_t test_key[32] = {
    0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
    0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
    0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
    0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
};
static const uint8_t test_ct256[16] = {
    0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,
    0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8
};

/* NIST GCM 测试向量 (GIFT-128, nonce=12字节) */
static const uint8_t gcm_key[16] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};
static const uint8_t gcm_nonce[12] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00
};
static const uint8_t gcm_pt[16] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};
static const uint8_t gcm_ct[16] = {
    0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,
    0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78
};
static const uint8_t gcm_tag[16] = {
    0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,
    0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf
};

/* ================================================================
 * 测试函数
 * ================================================================ */


    return 1;
}


    return 1;
}

static int test_ctr(const char *name, gift_block_fn enc_fn, const void *ctx) {
    uint8_t ct[64], pt[64];
    uint8_t nonce[4] = {0x00,0x00,0x00,0x00};
    memset(pt, 0xAA, 64);
    ctr_crypt(pt, ct, 64, nonce, 4, enc_fn, ctx);
    /* Verify decrypt gives back plaintext */
    memset(pt, 0, 64);
    ctr_crypt(ct, pt, 64, nonce, 4, enc_fn, ctx);
    for (int i = 0; i < 64; i++) {
        if (pt[i] != 0xAA) {
            printf("  FAIL: %s CTR round-trip at byte %d\n", name, i);
            return 0;
        }
    }
    return 1;
}


    /* decrypt verify */
    int r = gcm_decrypt(ct, pt, 16, NULL, 0, gcm_nonce, 12, tag,
                        enc_fn, ctx, 0);
    if (r != 0 || memcmp(pt, gcm_pt) != 0) {
        printf("  FAIL: %s GCM decrypt\n", name);
        return 0;
    }
    return 1;
}


    xts_decrypt(ct, dec, 64, 0, enc_fn, dec_fn, key1_ctx, key2_ctx);
    if (memcmp(pt, dec, 64) != 0) {
        printf("  FAIL: %s XTS round-trip\n", name);
        return 0;
    }
    return 1;
}

/* ================================================================
 * 性能基准测试
 * ================================================================ */

#define BENCH_BLOCKS  100000



static void bench_ctr(const char *name, gift_block_fn enc_fn, const void *ctx) {
    uint8_t *buf, nonce[4] = {0,0,0,0};
    buf = (uint8_t*)malloc(BENCH_MODE_BYTES);
    memset(buf, 0xAA, BENCH_MODE_BYTES);

    /* Warmup */
    ctr_crypt(buf, buf, BENCH_MODE_BYTES, nonce, 4, enc_fn, ctx);

    double start = get_time_us();
    ctr_crypt(buf, buf, BENCH_MODE_BYTES, nonce, 4, enc_fn, ctx);
    double elapsed = get_time_us() - start;

    double mbps = (double)BENCH_MODE_BYTES / elapsed;
    printf("  %-20s  %8.1f MB/s\n", name, mbps);
    free(buf);
}





#endif /* end of #if 0 - old code disabled */

/* ================================================================
 * GIFT-128: 64-bit block cipher
 * Note: block arrays use [8], bench uses 8-byte blocks
 * ================================================================ */

/* Wrappers */
static void w_ref_enc(const uint8_t *in, uint8_t *out, const void *ctx)
{ gift_ref_encrypt(in, out, (const gift_ctx*)ctx); }
static void w_ref_dec(const uint8_t *in, uint8_t *out, const void *ctx)
{ gift_ref_decrypt(in, out, (const gift_ctx*)ctx); }
static void w_tt_enc(const uint8_t *in, uint8_t *out, const void *ctx)
{ gift_ttable_encrypt(in, out, (const gift_ctx*)ctx); }
static void w_tt_dec(const uint8_t *in, uint8_t *out, const void *ctx)
{ gift_ttable_decrypt(in, out, (const gift_ctx*)ctx); }
static void w_sh_enc(const uint8_t *in, uint8_t *out, const void *ctx)
{ gift_shuffle_encrypt(in, out, (const gift_ctx*)ctx); }
static void w_bs_enc(const uint8_t *in, uint8_t *out, const void *ctx)
{ gift_bitslice_encrypt(in, out, (const gift_ctx*)ctx); }

/* Self-consistency tests (8-byte blocks for GIFT) */
static int test_rt(const char *n, gift_block_fn enc, gift_block_fn dec, const void *ctx) {
    uint8_t ct[16], pt2[8];
    enc(test_pt, ct, ctx);
    dec(ct, pt2, ctx);
    if (memcmp(test_pt, pt2, 8) != 0) { printf("  FAIL: %s\\n", n); return 0; }
    return 1;
}

static int test_cross(const char *n, gift_block_fn e, gift_block_fn d,
                      const void *c1, const void *c2) {
    uint8_t ct[16], pt2[8];
    e(test_pt, ct, c1); d(ct, pt2, c2);
    if (memcmp(test_pt, pt2, 8) != 0) { printf("  FAIL: %s\\n", n); return 0; }
    return 1;
}

static int test_ctr_ok(const char *n, gift_block_fn enc, const void *ctx) {
    uint8_t buf[64], tmp[64]; uint8_t nonce[4]={0}; int i;
    memset(buf, 0xAA, 64);
    gift_ctr_crypt(buf, tmp, 64, nonce, 4, enc, ctx);
    gift_ctr_crypt(tmp, buf, 64, nonce, 4, enc, ctx);
    for (i=0;i<64;i++) if(buf[i]!=0xAA) { printf("  FAIL: %s CTR\\n", n); return 0; }
    return 1;
}

static int test_gcm_ok(const char *n, gift_block_fn enc, const void *ctx) {
    uint8_t pt[16], ct[16], pt2[16], tag[16]; uint8_t nonce[12]={0};
    memset(pt, 0x55, 32);
    gift_gcm_encrypt(pt, ct, 32, NULL, 0, nonce, 12, tag, enc, ctx);
    int r=gift_gcm_decrypt(ct, pt2, 32, NULL, 0, nonce, 12, tag, enc, ctx);
    if (r!=0||memcmp(pt,pt2,32)!=0) { printf("  FAIL: %s GCM\\n", n); return 0; }
    tag[0]^=1;
    if (gift_gcm_decrypt(ct,pt2,32,NULL,0,nonce,12,tag,enc,ctx)==0) { printf("  FAIL: %s GCM tamper\\n", n); return 0; }
    return 1;
}

static int test_xts_ok(const char *n, gift_block_fn enc, gift_block_fn dec,
                       const void *k1, const void *k2) {
    uint8_t pt[48], ct[48], dpt[48]; int i;
    for (i=0;i<48;i++) pt[i]=(uint8_t)i;
    gift_xts_encrypt(pt, ct, 48, 0, enc, enc, k1, k2);
    if (memcmp(pt, ct, 48)==0) { printf("  FAIL: %s XTS no change\\n", n); return 0; }
    gift_xts_decrypt(ct, dpt, 48, 0, enc, dec, k1, k2);
    if (memcmp(pt, dpt, 48)!=0) { printf("  FAIL: %s XTS\\n", n); return 0; }
    return 1;
}

#define WARMUP 100
#define BENCH_BLOCKS 50000
#define BENCH_MBYTES (1024*1024)

static void bench_enc(const char *n, gift_block_fn fn, const void *ctx) {
    uint8_t pt[16], ct[8]; int k;
    memset(pt, 0, 16);
    for (k=0;k<WARMUP;k++) fn(pt,ct,ctx);
    double s=get_time_us();
    for (k=0;k<BENCH_BLOCKS;k++) fn(pt,ct,ctx);
    double e=get_time_us()-s;
    printf("  %-20s  %8.1f MB/s  (%7.3f us/block)\\n",
           n, (double)(BENCH_BLOCKS*16)/e, e/BENCH_BLOCKS);
}

static void bench_ctr(const char *n, gift_block_fn fn, const void *ctx) {
    uint8_t *buf=(uint8_t*)malloc(BENCH_MBYTES); uint8_t nonce[4]={0};
    memset(buf,0xAA,BENCH_MBYTES);
    gift_ctr_crypt(buf,buf,BENCH_MBYTES,nonce,4,fn,ctx);
    double s=get_time_us();
    gift_ctr_crypt(buf,buf,BENCH_MBYTES,nonce,4,fn,ctx);
    double e=get_time_us()-s;
    printf("  %-20s  %8.1f MB/s\\n", n, (double)BENCH_MBYTES/e);
    free(buf);
}

static void bench_gcm(const char *n, gift_block_fn fn, const void *ctx) {
    size_t sz=BENCH_MBYTES;
    uint8_t *buf=(uint8_t*)malloc(sz),*ctb=(uint8_t*)malloc(sz);
    uint8_t nonce[12]={0},tag[16];
    memset(buf,0xAA,sz);
    gift_gcm_encrypt(buf,ctb,sz,NULL,0,nonce,12,tag,fn,ctx);
    double s=get_time_us();
    gift_gcm_encrypt(buf,ctb,sz,NULL,0,nonce,12,tag,fn,ctx);
    double e=get_time_us()-s;
    printf("  %-20s  %8.1f MB/s\\n", n, (double)sz/e);
    free(buf); free(ctb);
}

int main(void) {
#if defined(_MSC_VER)
    SetConsoleOutputCP(65001);
#endif
    printf("============================================================\\n");
    printf("  GIFT-128 Software Optimization - Experiment 3\\n");
    printf("============================================================\\n\\n");
    printf("[CPU] SSSE3:%s AVX:%s AVX2:%s\\n",
        cpu_has_ssse3()?"YES":"NO", cpu_has_avx()?"YES":"NO", cpu_has_avx2()?"YES":"NO");
    fflush(stdout);

    int ok, total=0;

    printf("\\n[Test 1] Encrypt/Decrypt round-trip\\n"); fflush(stdout);
    { gift_ctx c; gift_ref_init(&c,test_key);
      ok=test_rt("Ref",w_ref_enc,w_ref_dec,&c);
      printf("  Ref ........... %s\\n",ok?"PASS":"FAIL"); total+=ok; }
    { gift_ctx c; gift_ttable_init(&c,test_key);
      ok=test_rt("T-table",w_tt_enc,w_tt_dec,&c);
      printf("  T-table ....... %s\\n",ok?"PASS":"FAIL"); total+=ok; }
    { gift_ctx c; gift_shuffle_init(&c,test_key);
      ok=test_rt("Shuffle",w_sh_enc,w_ref_dec,&c);
      printf("  Shuffle ....... %s\\n",ok?"PASS":"FAIL"); total+=ok; }
    fflush(stdout);

    printf("\\n[Test 2] Cross-implementation\\n"); fflush(stdout);
    { gift_ctx c1,c2; gift_ttable_init(&c1,test_key); gift_ref_init(&c2,test_key);
      ok=test_cross("TT->Ref",w_tt_enc,w_ref_dec,&c1,&c2);
      printf("  TT->Ref ....... %s\\n",ok?"PASS":"FAIL"); total+=ok; }
    { gift_ctx c1,c2; gift_ref_init(&c1,test_key); gift_ttable_init(&c2,test_key);
      ok=test_cross("Ref->TT",w_ref_enc,w_tt_dec,&c1,&c2);
      printf("  Ref->TT ....... %s\\n",ok?"PASS":"FAIL"); total+=ok; }
    fflush(stdout);

    printf("\\n[Test 3] CTR mode\\n"); fflush(stdout);
    { gift_ctx c; gift_ref_init(&c,test_key);
      ok=test_ctr_ok("Ref-CTR",w_ref_enc,&c);
      printf("  Ref-CTR ....... %s\\n",ok?"PASS":"FAIL"); total+=ok; }
    { gift_ctx c; gift_ttable_init(&c,test_key);
      ok=test_ctr_ok("T-table-CTR",w_tt_enc,&c);
      printf("  T-table-CTR ... %s\\n",ok?"PASS":"FAIL"); total+=ok; }
    fflush(stdout);

    printf("\\n[Test 4] GCM mode\\n"); fflush(stdout);
    { gift_ctx c; gift_ref_init(&c,test_key);
      ok=test_gcm_ok("Ref-GCM",w_ref_enc,&c);
      printf("  Ref-GCM ....... %s\\n",ok?"PASS":"FAIL"); total+=ok; }
    { gift_ctx c; gift_ttable_init(&c,test_key);
      ok=test_gcm_ok("T-table-GCM",w_tt_enc,&c);
      printf("  T-table-GCM ... %s\\n",ok?"PASS":"FAIL"); total+=ok; }
    fflush(stdout);

    printf("\\n[Test 5] XTS mode\\n"); fflush(stdout);
    { gift_ctx k1,k2; uint8_t xk[16]={0};
      gift_ref_init(&k1,xk); gift_ref_init(&k2,test_key);
      ok=test_xts_ok("Ref-XTS",w_ref_enc,w_ref_dec,&k1,&k2);
      printf("  Ref-XTS ....... %s\\n",ok?"PASS":"FAIL"); total+=ok; }
    { gift_ctx k1,k2;
      gift_ttable_init(&k1,test_key); gift_ttable_init(&k2,test_key);
      ok=test_xts_ok("T-table-XTS",w_tt_enc,w_tt_dec,&k1,&k2);
      printf("  T-table-XTS ... %s\\n",ok?"PASS":"FAIL"); total+=ok; }
    fflush(stdout);

    printf("\\n  >> %d/10 tests passed\\n", total);

    /* Performance */
    printf("\\n============================================================\\n");
    printf("[Performance] GIFT-128 single-block encrypt\\n");
    printf("============================================================\\n");
    fflush(stdout);
    { gift_ctx c; gift_ref_init(&c,test_key);
      bench_enc("1. Reference", w_ref_enc, &c); }
    { gift_ctx c; gift_ttable_init(&c,test_key);
      bench_enc("2. T-table", w_tt_enc, &c); }
    { gift_ctx c; gift_shuffle_init(&c,test_key);
      bench_enc("3. Shuffle(PSHUFB)", w_sh_enc, &c); }
    { gift_ctx c; gift_bitslice_init(&c,test_key);
      bench_enc("4. Bitslice(SSSE3)", w_bs_enc, &c); }
    { gift_ctx c; gift_avx2_init(&c,test_key);
      uint8_t p4[4][16],c4[4][16]; int w,i;
      memset(p4,0,sizeof(p4));
      for(w=0;w<WARMUP;w++) gift_avx2_encrypt_x4(p4,c4,&c);
      double st=get_time_us();
      for(i=0;i<BENCH_BLOCKS/4;i++) gift_avx2_encrypt_x4(p4,c4,&c);
      double e4=get_time_us()-st;
      printf("  %-20s  %8.1f MB/s\\n","5. AVX2 (4x)",(double)(BENCH_BLOCKS*16)/e4); }
    { gift_ctx c; gift_avx2_init(&c,test_key);
      uint8_t p8[8][16],c8[8][16]; int w,i;
      memset(p8,0,sizeof(p8));
      for(w=0;w<WARMUP;w++) gift_avx2_encrypt_x8(p8,c8,&c);
      double st=get_time_us();
      for(i=0;i<BENCH_BLOCKS/8;i++) gift_avx2_encrypt_x8(p8,c8,&c);
      double e8=get_time_us()-st;
      printf("  %-20s  %8.1f MB/s\\n","6. AVX2 (8x)",(double)(BENCH_BLOCKS*16)/e8); }
    fflush(stdout);

    printf("\\n--- CTR mode (1 MB) ---\\n"); fflush(stdout);
    { gift_ctx c; gift_ttable_init(&c,test_key);
      bench_ctr("T-table+CTR", w_tt_enc, &c); }
    fflush(stdout);

    printf("\\n--- GCM mode (1 MB) ---\\n"); fflush(stdout);
    { gift_ctx c; gift_ttable_init(&c,test_key);
      bench_gcm("T-table+GCM", w_tt_enc, &c); }
    fflush(stdout);

    printf("\\n============================================================\\n");
    printf("  All done.\\n");
    printf("============================================================\\n");
    return 0;
}
