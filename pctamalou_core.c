/*
 * PCTamalou Complex Cipher v0.4 – Noyau C optimisé (corrigé)
 * ===========================================================
 * Ajout de fp2_sqr, correction des initialisations.
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

typedef uint64_t u64;
typedef unsigned __int128 u128;

typedef struct { u64 l[4]; } fp_t;
typedef struct { fp_t a; fp_t b; } fp2_t;

static const fp_t FP_P = {{0xFFFFFFFFFFFFFFEDULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0x7FFFFFFFFFFFFFFFULL}};
    static const fp_t FP_ZERO = {{0,0,0,0}};
    static const fp_t FP_ONE  = {{1,0,0,0}};

    /* ------------------------------------------------------------------ */
    static inline int fp_is_zero(const fp_t *x) {
        return (x->l[0] | x->l[1] | x->l[2] | x->l[3]) == 0;
    }

    static void fp_add(fp_t *r, const fp_t *a, const fp_t *b) {
        u128 t; u64 carry = 0;
        for (int i = 0; i < 4; i++) {
            t = (u128)a->l[i] + b->l[i] + carry;
            r->l[i] = (u64)t; carry = (u64)(t >> 64);
        }
        if (carry || (r->l[3] == FP_P.l[3] && r->l[2] == FP_P.l[2] &&
            r->l[1] == FP_P.l[1] && r->l[0] >= FP_P.l[0])) {
            t = (u128)r->l[0] + 19; r->l[0] = (u64)t; carry = (u64)(t >> 64);
        for (int i = 1; i < 4; i++) {
            t = (u128)r->l[i] + carry; r->l[i] = (u64)t; carry = (u64)(t >> 64);
        }
        r->l[3] &= 0x7FFFFFFFFFFFFFFFULL;
            }
    }

    static void fp_sub(fp_t *r, const fp_t *a, const fp_t *b) {
        u128 t; u64 borrow = 0;
        for (int i = 0; i < 4; i++) {
            t = (u128)a->l[i] - b->l[i] - borrow;
            r->l[i] = (u64)t; borrow = (u64)(t >> 127) & 1;
        }
        if (borrow) {
            u64 carry = 0;
            t = (u128)r->l[0] + FP_P.l[0]; r->l[0] = (u64)t; carry = (u64)(t >> 64);
            for (int i = 1; i < 4; i++) {
                t = (u128)r->l[i] + FP_P.l[i] + carry; r->l[i] = (u64)t; carry = (u64)(t >> 64);
            }
        }
    }

    static void fp_mul(fp_t *r, const fp_t *a, const fp_t *b) {
        u128 t, c[8] = {0};
        for (int i = 0; i < 4; i++) {
            u64 carry = 0;
            for (int j = 0; j < 4; j++) {
                t = (u128)a->l[i] * b->l[j] + c[i+j] + carry;
                c[i+j] = (u64)t; carry = (u64)(t >> 64);
            }
            c[i+4] += carry;
        }
        u64 lo[4] = {c[0],c[1],c[2],c[3]};
        u64 hi[4] = {c[4],c[5],c[6],c[7]};
        u64 bit255 = (lo[3] >> 63); lo[3] &= 0x7FFFFFFFFFFFFFFFULL;

        u64 carry = 0;
        for (int i = 0; i < 4; i++) {
            t = (u128)hi[i] * 38ULL + lo[i] + carry;
            r->l[i] = (u64)t; carry = (u64)(t >> 64);
        }
        t = (u128)carry * 38ULL + bit255 * 19ULL + r->l[0];
        r->l[0] = (u64)t; carry = (u64)(t >> 64);
        for (int i = 1; i < 4; i++) {
            t = (u128)r->l[i] + carry; r->l[i] = (u64)t; carry = (u64)(t >> 64);
        }
        if (r->l[3] > 0x7FFFFFFFFFFFFFFFULL ||
            (r->l[3] == 0x7FFFFFFFFFFFFFFFULL && r->l[2] == 0xFFFFFFFFFFFFFFFFULL &&
            r->l[1] == 0xFFFFFFFFFFFFFFFFULL && r->l[0] >= 0xFFFFFFFFFFFFFFEDULL)) {
            t = (u128)r->l[0] + 19; r->l[0] = (u64)t; carry = (u64)(t >> 64);
        for (int i = 1; i < 4; i++) {
            t = (u128)r->l[i] + carry; r->l[i] = (u64)t; carry = (u64)(t >> 64);
        }
        r->l[3] &= 0x7FFFFFFFFFFFFFFFULL;
            }
    }

    static void fp_sqr(fp_t *r, const fp_t *a) { fp_mul(r, a, a); }

    static void fp_inv(fp_t *r, const fp_t *a) {
        if (fp_is_zero(a)) { *r = FP_ONE; return; }
        fp_t base, res = FP_ONE;
        memcpy(&base, a, sizeof(fp_t));
        u64 exp[4] = {0xFFFFFFFFFFFFFFEBULL, 0xFFFFFFFFFFFFFFFFULL,
            0xFFFFFFFFFFFFFFFFULL, 0x7FFFFFFFFFFFFFFFULL};
            for (int i = 0; i < 256; i++) {
                if ((exp[i>>6] >> (i&63)) & 1) fp_mul(&res, &res, &base);
                fp_sqr(&base, &base);
            }
            memcpy(r, &res, sizeof(fp_t));
    }

    /* Fp² */
    static void fp2_add(fp2_t *r, const fp2_t *a, const fp2_t *b) {
        fp_add(&r->a, &a->a, &b->a); fp_add(&r->b, &a->b, &b->b);
    }
    static void fp2_sub(fp2_t *r, const fp2_t *a, const fp2_t *b) {
        fp_sub(&r->a, &a->a, &b->a); fp_sub(&r->b, &a->b, &b->b);
    }
    static void fp2_mul(fp2_t *r, const fp2_t *a, const fp2_t *b) {
        fp_t t0,t1,t2,t3;
        fp_mul(&t0, &a->a, &b->a); fp_mul(&t1, &a->b, &b->b);
        fp_mul(&t2, &a->a, &b->b); fp_mul(&t3, &a->b, &b->a);
        fp_sub(&r->a, &t0, &t1); fp_add(&r->b, &t2, &t3);
    }
    static void fp2_sqr(fp2_t *r, const fp2_t *a) {
        /* (a+bi)² = (a² - b²) + 2ab·i */
        fp_t t0, t1, t2;
        fp_sqr(&t0, &a->a);
        fp_sqr(&t1, &a->b);
        fp_mul(&t2, &a->a, &a->b);
        fp_sub(&r->a, &t0, &t1);
        fp_add(&r->b, &t2, &t2);
    }
    static void fp2_inv(fp2_t *r, const fp2_t *a) {
        fp_t norm, inv_norm, aa, bb;
        fp_sqr(&aa, &a->a); fp_sqr(&bb, &a->b);
        fp_add(&norm, &aa, &bb);
        if (fp_is_zero(&norm)) { r->a = FP_ONE; r->b = FP_ZERO; return; }
        fp_inv(&inv_norm, &norm);
        fp_mul(&r->a, &a->a, &inv_norm);
        fp_t nb; fp_sub(&nb, &FP_ZERO, &a->b);
        fp_mul(&r->b, &nb, &inv_norm);
    }

    /* Batch inversion */
    static void fp2_batch_inv(fp2_t *out, const fp2_t *in, int n) {
        if (n == 0) return;
        fp2_t *prefix = malloc(n * sizeof(fp2_t));
        prefix[0] = in[0];
        for (int i = 1; i < n; i++) fp2_mul(&prefix[i], &prefix[i-1], &in[i]);
        fp2_t inv_total; fp2_inv(&inv_total, &prefix[n-1]);
        fp2_t tmp;
        for (int i = n-1; i > 0; i--) {
            fp2_mul(&out[i], &inv_total, &prefix[i-1]);
            fp2_mul(&tmp, &inv_total, &in[i]);
            inv_total = tmp;
        }
        out[0] = inv_total;
        free(prefix);
    }

    /* ====================================================================
     * Constantes mathématiques
     * ==================================================================== */
    #define NROOTS 8
    #define NREG 24

    static const fp2_t ROOTS[NROOTS] = {
        { .a = {{1,0,0,0}}, .b = {{0,0,0,0}} },
        { .a = {{0xC4E4DD72F8A2E2BDULL,0xA30F96BC9B46A07CULL,0x92D41B2E90FF87C8ULL,0x5A827999FCEF3243ULL}},
        .b = {{0xC4E4DD72F8A2E2BDULL,0xA30F96BC9B46A07CULL,0x92D41B2E90FF87C8ULL,0x5A827999FCEF3243ULL}} },
        { .a = {{0,0,0,0}}, .b = {{1,0,0,0}} },
        { .a = {{0xFFFFFFFFFFFFFFECULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,0x7FFFFFFFFFFFFFFFULL}},
        .b = {{0xC4E4DD72F8A2E2BDULL,0xA30F96BC9B46A07CULL,0x92D41B2E90FF87C8ULL,0x5A827999FCEF3243ULL}} },
        { .a = {{0xFFFFFFFFFFFFFFECULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,0x7FFFFFFFFFFFFFFFULL}}, .b = {{0,0,0,0}} },
        { .a = {{0xFFFFFFFFFFFFFFECULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,0x7FFFFFFFFFFFFFFFULL}},
        .b = {{0xFFFFFFFFFFFFFFECULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,0x7FFFFFFFFFFFFFFFULL}} },
        { .a = {{0,0,0,0}}, .b = {{0xFFFFFFFFFFFFFFECULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,0x7FFFFFFFFFFFFFFFULL}} },
        { .a = {{0xC4E4DD72F8A2E2BDULL,0xA30F96BC9B46A07CULL,0x92D41B2E90FF87C8ULL,0x5A827999FCEF3243ULL}},
        .b = {{0xFFFFFFFFFFFFFFECULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,0x7FFFFFFFFFFFFFFFULL}} }
    };

    static const fp2_t ZETA[NROOTS] = {
        { .a = {{0xCE0B6B2B4FA6C933ULL,0x1A8F3E2D7C501B44ULL,0x9D2E4F1A3C8B7E05ULL,0x3A4C8D2F1B7E9A06ULL}}, .b = {{0,0,0,0}} },
        { .a = {{0x90744B74FEF94736ULL,0x6E5F3A2C1D8B7E04ULL,0xA3C8D2F1B7E9A061ULL,0x2F4C8D2F1B7E9A06ULL}},
        .b = {{0xAEAC18558F1CF3ADULL,0x3D2E4F1A3C8B7E05ULL,0x8C2F1B7E9A061D4EULL,0x1E4C8D2F1B7E9A06ULL}} },
        { .a = {{0x847CBEB87E9A3575ULL,0x5C1D8B7E04A3C8D2ULL,0x7E9A061D4E2F1B7EULL,0x0D4C8D2F1B7E9A06ULL}},
        .b = {{0xED7E00FF3A49FF89ULL,0x4B2E4F1A3C8B7E05ULL,0x6A061D4E2F1B7E9AULL,0x5B4C8D2F1B7E9A06ULL}} },
        { .a = {{0x2F5FD62F0FE1EC10ULL,0x2A1A3C8B7E04A3C8ULL,0x5B7E9A061D4E2F1BULL,0x4A4C8D2F1B7E9A06ULL}},
        .b = {{0xBB58B1FC9BBB3B7DULL,0x192E4F1A3C8B7E05ULL,0x3A061D4E2F1B7E9AULL,0x294C8D2F1B7E9A06ULL}} },
        { .a = {{0,0,0,0}}, .b = {{0,0,0,0}} },
        { .a = {{0x3AEA72CB93FE1F1EULL,0x082E4F1A3C8B7E04ULL,0x2A061D4E2F1B7E9AULL,0x184C8D2F1B7E9A06ULL}},
        .b = {{0xCAF01D5985B3CC24ULL,0x7F1A3C8B7E04A3C8ULL,0x1061D4E2F1B7E9A0ULL,0x074C8D2F1B7E9A06ULL}} },
        { .a = {{0xCCB4B7E3DD63F49CULL,0x6E0A3C8B7E04A3C8ULL,0x0061D4E2F1B7E9A0ULL,0x664C8D2F1B7E9A06ULL}},
        .b = {{0x3622DF7D96FA19EBULL,0x5CFA3C8B7E04A3C8ULL,0xF061D4E2F1B7E9A0ULL,0x554C8D2F1B7E9A06ULL}} },
        { .a = {{0x6016C4C2B9FBADULL,0x4CEA3C8B7E04A3C8ULL,0xE061D4E2F1B7E9A0ULL,0x444C8D2F1B7E9A06ULL}},
        .b = {{0xF48B6D1374E9B617ULL,0x3BDA3C8B7E04A3C8ULL,0xD061D4E2F1B7E9A0ULL,0x334C8D2F1B7E9A06ULL}} }
    };

    static fp2_t PRE_ZETA_DW[NROOTS];
    static fp2_t INV_N;
    static fp2_t DW[NROOTS];

    static int g_initialized = 0;
    static void pct_init(void) {
        if (g_initialized) return;
        fp_t n = {{NROOTS,0,0,0}};
        fp_t inv_n_fp; fp_inv(&inv_n_fp, &n);
        INV_N.a = inv_n_fp; INV_N.b = FP_ZERO;

        for (int k = 0; k < NROOTS; k++) {
            fp2_sub(&DW[k], &ROOTS[(k+1)%NROOTS], &ROOTS[k]);
            fp2_mul(&PRE_ZETA_DW[k], &ZETA[k], &DW[k]);
        }
        g_initialized = 1;
    }

    /* ====================================================================
     * Permutation optimisée
     * ==================================================================== */
    static void pct_permutation(fp2_t regs[NREG]) {
        fp2_t new_regs[NREG];
        memcpy(new_regs, regs, sizeof(new_regs));

        for (int k = 0; k < NROOTS; k++) {
            fp2_t diff[NREG];
            int active[NREG], n_active = 0;
            for (int i = 0; i < NREG; i++) {
                fp2_sub(&diff[i], &ROOTS[k], &regs[i]);
                active[i] = !fp_is_zero(&diff[i].a) || !fp_is_zero(&diff[i].b);
                if (active[i]) n_active++;
            }
            if (n_active == 0) continue;

            fp2_t *diff_active = malloc(n_active * sizeof(fp2_t));
            fp2_t *inv_diff = malloc(n_active * sizeof(fp2_t));
            int idx = 0;
            for (int i = 0; i < NREG; i++) if (active[i]) diff_active[idx++] = diff[i];
            fp2_batch_inv(inv_diff, diff_active, n_active);

            idx = 0;
            for (int i = 0; i < NREG; i++) {
                if (!active[i]) continue;
                fp2_t fw, tmp;
                fp2_mul(&fw, &regs[i], &ROOTS[k]);
                fp2_mul(&tmp, &PRE_ZETA_DW[k], &fw);
                fp2_mul(&tmp, &tmp, &inv_diff[idx++]);
                fp2_add(&new_regs[i], &new_regs[i], &tmp);
            }
            free(diff_active); free(inv_diff);
        }

        for (int i = 0; i < NREG; i++)
            fp2_mul(&new_regs[i], &new_regs[i], &INV_N);

        for (int i = 0; i < NREG; i++) {
            u64 r_idx = new_regs[i].a.l[0] % NROOTS;
            u64 i_idx = new_regs[i].b.l[0] % NROOTS;
            fp2_t tmp;
            fp2_mul(&tmp, &new_regs[i], &ROOTS[r_idx]);
            fp2_add(&new_regs[i], &tmp, &ROOTS[i_idx]);
        }

        for (int i = 0; i < NREG; i++) {
            for (int limb = 0; limb < 4; limb++) {
                u64 a = new_regs[i].a.l[limb];
                u64 b = new_regs[i].b.l[limb];
                a ^= (a >> 23) ^ (b << 7) ^ (new_regs[i].a.l[(limb+1)%4] >> 13);
                b ^= (b >> 17) ^ (a << 11) ^ (new_regs[i].b.l[(limb+2)%4] << 5);
                new_regs[i].a.l[limb] = a;
                new_regs[i].b.l[limb] = b;
            }
        }
        memcpy(regs, new_regs, sizeof(new_regs));
    }

    /* ====================================================================
     * Hash Sponge
     * ==================================================================== */
    void pct_hash(const uint8_t *data, size_t len, uint8_t *out, size_t out_len) {
        pct_init();
        fp2_t regs[NREG];
        for (int i = 0; i < NREG; i++)
            fp2_add(&regs[i], &ROOTS[i % NROOTS], &ZETA[i % NROOTS]);

        size_t offset = 0;
        while (offset < len || offset == 0) {
            uint8_t block[32] = {0};
            size_t take = (len - offset > 32) ? 32 : len - offset;
            if (take) memcpy(block, data + offset, take);
            if (take < 32) block[take] = 0x80;

            for (int i = 0; i < 16; i++) {
                fp2_t pt;
                pt.a = (fp_t){{ block[2*i], 0, 0, 0 }};
                pt.b = (fp_t){{ block[2*i+1], 0, 0, 0 }};
                int idx = (i * 7) % NREG;
                fp2_add(&regs[idx], &regs[idx], &pt);
            }
            pct_permutation(regs);
            offset += take;
            if (take < 32) break;
        }

        for (int r = 0; r < 6; r++) pct_permutation(regs);

        size_t pos = 0;
        int pass = 0;
        while (pos < out_len) {
            if (pass) pct_permutation(regs);
            for (int i = 0; i < NREG && pos < out_len; i++) {
                for (int limb = 3; limb >= 0; limb--) {
                    u64 v = regs[i].a.l[limb] ^ regs[i].b.l[limb];
                    for (int j = 0; j < 8 && pos < out_len; j++)
                        out[pos++] = (v >> (8*j)) & 0xFF;
                }
            }
            pass++;
        }
    }

    /* ====================================================================
     * Stream Feistel + MAC + AEAD + KDF (complet)
     * ==================================================================== */
    typedef struct {
        fp2_t L, R;
        uint8_t buf[32];
        int buf_pos;
        uint64_t counter;
    } pct_stream_ctx;

    static void pct_stream_squeeze(pct_stream_ctx *ctx) {
        for (int r = 0; r < 12; r++) {
            fp2_t sq; fp2_sqr(&sq, &ctx->R);
            fp2_add(&ctx->L, &ctx->L, &sq);
            fp2_add(&ctx->L, &ctx->L, &ROOTS[ctx->counter % NROOTS]);
            fp2_t tmp = ctx->L; ctx->L = ctx->R; ctx->R = tmp;
            ctx->counter++;
        }
        for (int i = 0; i < 32; i++)
            ctx->buf[i] = (ctx->L.a.l[i%4] ^ ctx->R.b.l[i%4]) & 0xFF;
        ctx->buf_pos = 0;
    }

    void pct_stream_init(pct_stream_ctx *ctx, const uint8_t *key, size_t key_len,
                         const uint8_t *nonce, size_t nonce_len) {
        pct_init();
        uint8_t seed[64];
        uint8_t tmp[1 + key_len + nonce_len];
        tmp[0] = 0x01;
        memcpy(tmp+1, key, key_len);
        memcpy(tmp+1+key_len, nonce, nonce_len);
        pct_hash(tmp, sizeof(tmp), seed, 64);

        memset(&ctx->L, 0, sizeof(fp2_t));
        memset(&ctx->R, 0, sizeof(fp2_t));
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 8; j++) {
                ctx->L.a.l[i] |= (u64)seed[i*8 + j] << (8*j);
                ctx->R.a.l[i] |= (u64)seed[32 + i*8 + j] << (8*j);
            }
        }
        ctx->buf_pos = 32;
        ctx->counter = 0;
                         }

                         uint8_t pct_stream_byte(pct_stream_ctx *ctx) {
                             if (ctx->buf_pos >= 32) pct_stream_squeeze(ctx);
                             return ctx->buf[ctx->buf_pos++];
                         }

                         /* MAC polynomial */
                         void pct_mac(const uint8_t *data, size_t len, const uint8_t *key, size_t key_len,
                                      uint8_t *tag, size_t tag_len) {
                             pct_init();
                             uint8_t rs_buf[64];
                             uint8_t mac_key[1 + key_len];
                             mac_key[0] = 0x02;
                             memcpy(mac_key+1, key, key_len);
                             pct_hash(mac_key, sizeof(mac_key), rs_buf, 64);

                             fp2_t r, s, acc;
                             memset(&r, 0, sizeof(r));
                             memset(&s, 0, sizeof(s));
                             memset(&acc, 0, sizeof(acc));
                             for (int i = 0; i < 4; i++) {
                                 for (int j = 0; j < 8; j++) {
                                     if (i*8+j < 32) r.a.l[i] |= (u64)rs_buf[i*8+j] << (8*j);
                                     if (32+i*8+j < 64) s.a.l[i] |= (u64)rs_buf[32+i*8+j] << (8*j);
                                 }
                             }
                             r.a.l[3] &= 0x0FFFFFFFFFFFFFFFULL;
                             r.b = FP_ZERO;
                             s.b = FP_ZERO;

                             for (size_t off = 0; off < len || off == 0; ) {
                                 uint8_t blk[16] = {0};
                                 size_t take = (len - off > 16) ? 16 : len - off;
                                 if (take) memcpy(blk, data + off, take);
                                 off += take;

                                 fp2_t m;
                                 memset(&m, 0, sizeof(m));
                                 for (int i = 0; i < 16; i++) {
                                     if (i < 8) m.a.l[i/8] |= (u64)blk[i] << (8*(i%8));
                                     else      m.b.l[(i-8)/8] |= (u64)blk[i] << (8*((i-8)%8));
                                 }
                                 if (take < 16) m.a.l[take/8] |= (u64)1 << (8*(take%8));

                                 fp2_add(&acc, &acc, &m);
                                 fp2_mul(&acc, &acc, &r);
                                 if (off >= len) break;
                             }
                             fp2_add(&acc, &acc, &s);

                             for (size_t i = 0; i < tag_len && i < 64; i++) {
                                 tag[i] = (i < 32) ? (acc.a.l[i/8] >> (8*(i%8))) & 0xFF
                                 : (acc.b.l[(i-32)/8] >> (8*((i-32)%8))) & 0xFF;
                             }
                                      }

                                      /* AEAD */
                                      #define PCT_NONCE_LEN 16
                                      #define PCT_TAG_LEN 32

                                      size_t pct_encrypt(const uint8_t *key, size_t key_len,
                                                         const uint8_t *nonce_in,
                                                         const uint8_t *plain, size_t plain_len,
                                                         uint8_t *out) {
                                          uint8_t nonce[PCT_NONCE_LEN];
                                          if (nonce_in) memcpy(nonce, nonce_in, PCT_NONCE_LEN);
                                          else {
                                              FILE *f = fopen("/dev/urandom", "rb");
                                              if (f && fread(nonce, 1, PCT_NONCE_LEN, f) == PCT_NONCE_LEN) fclose(f);
                                              else pct_hash(key, key_len, nonce, PCT_NONCE_LEN);
                                          }
                                          memcpy(out, nonce, PCT_NONCE_LEN);

                                          uint8_t *ct = out + PCT_NONCE_LEN;
                                          pct_stream_ctx sctx;
                                          pct_stream_init(&sctx, key, key_len, nonce, PCT_NONCE_LEN);
                                          for (size_t i = 0; i < plain_len; i++)
                                              ct[i] = plain[i] ^ pct_stream_byte(&sctx);

                                          uint8_t mac_input[PCT_NONCE_LEN + plain_len];
                                          memcpy(mac_input, nonce, PCT_NONCE_LEN);
                                          memcpy(mac_input + PCT_NONCE_LEN, ct, plain_len);
                                          pct_mac(mac_input, sizeof(mac_input), key, key_len,
                                                  out + PCT_NONCE_LEN + plain_len, PCT_TAG_LEN);
                                          return plain_len + PCT_NONCE_LEN + PCT_TAG_LEN;
                                                         }

                                                         int64_t pct_decrypt(const uint8_t *key, size_t key_len,
                                                                             const uint8_t *cipher, size_t cipher_len,
                                                                             uint8_t *plain) {
                                                             if (cipher_len < PCT_NONCE_LEN + PCT_TAG_LEN) return -1;
                                                             const uint8_t *nonce = cipher;
                                                             const uint8_t *ct = cipher + PCT_NONCE_LEN;
                                                             size_t pt_len = cipher_len - PCT_NONCE_LEN - PCT_TAG_LEN;
                                                             const uint8_t *tag_in = cipher + PCT_NONCE_LEN + pt_len;

                                                             uint8_t mac_input[PCT_NONCE_LEN + pt_len];
                                                             memcpy(mac_input, nonce, PCT_NONCE_LEN);
                                                             memcpy(mac_input + PCT_NONCE_LEN, ct, pt_len);
                                                             uint8_t tag_calc[PCT_TAG_LEN];
                                                             pct_mac(mac_input, sizeof(mac_input), key, key_len, tag_calc, PCT_TAG_LEN);

                                                             uint8_t diff = 0;
                                                             for (int i = 0; i < PCT_TAG_LEN; i++) diff |= tag_calc[i] ^ tag_in[i];
                                                             if (diff) return -1;

                                                             pct_stream_ctx sctx;
                                                             pct_stream_init(&sctx, key, key_len, nonce, PCT_NONCE_LEN);
                                                             for (size_t i = 0; i < pt_len; i++)
                                                                 plain[i] = ct[i] ^ pct_stream_byte(&sctx);
                                                             return (int64_t)pt_len;
                                                                             }

                                                                             /* KDF */
                                                                             void pct_kdf(const uint8_t *secret, size_t secret_len,
                                                                                          const uint8_t *salt, size_t salt_len,
                                                                                          uint32_t iterations, uint8_t *out, size_t out_len) {
                                                                                 pct_init();
                                                                                 size_t seed_len = 1 + secret_len + salt_len;
                                                                                 uint8_t *seed = malloc(seed_len);
                                                                                 seed[0] = 0x03;
                                                                                 memcpy(seed+1, secret, secret_len);
                                                                                 memcpy(seed+1+secret_len, salt, salt_len);
                                                                                 uint8_t state[64];
                                                                                 pct_hash(seed, seed_len, state, 64);
                                                                                 free(seed);

                                                                                 for (uint32_t i = 0; i < iterations; i++) {
                                                                                     uint8_t iter_input[64 + salt_len + 4];
                                                                                     memcpy(iter_input, state, 64);
                                                                                     memcpy(iter_input + 64, salt, salt_len);
                                                                                     iter_input[64 + salt_len]     = (i >> 24) & 0xFF;
                                                                                     iter_input[64 + salt_len + 1] = (i >> 16) & 0xFF;
                                                                                     iter_input[64 + salt_len + 2] = (i >> 8)  & 0xFF;
                                                                                     iter_input[64 + salt_len + 3] = i & 0xFF;
                                                                                     pct_hash(iter_input, sizeof(iter_input), state, 64);
                                                                                 }

                                                                                 size_t pos = 0; uint32_t ctr = 0;
                                                                                 while (pos < out_len) {
                                                                                     uint8_t blk[64 + 4];
                                                                                     memcpy(blk, state, 64);
                                                                                     blk[64] = (ctr >> 24) & 0xFF; blk[65] = (ctr >> 16) & 0xFF;
                                                                                     blk[66] = (ctr >> 8) & 0xFF;  blk[67] = ctr & 0xFF;
                                                                                     uint8_t blk_out[64];
                                                                                     pct_hash(blk, sizeof(blk), blk_out, 64);
                                                                                     size_t take = (out_len - pos > 64) ? 64 : out_len - pos;
                                                                                     memcpy(out + pos, blk_out, take);
                                                                                     pos += take; ctr++;
                                                                                 }
                                                                                          }

                                                                                          /* API exportée */
                                                                                          void PCT_hash(const uint8_t *data, uint32_t data_len, uint8_t *out, uint32_t out_len) {
                                                                                              pct_hash(data, data_len, out, out_len);
                                                                                          }
                                                                                          void PCT_kdf(const uint8_t *secret, uint32_t secret_len,
                                                                                                       const uint8_t *salt, uint32_t salt_len,
                                                                                                       uint32_t iterations, uint8_t *out, uint32_t out_len) {
                                                                                              pct_kdf(secret, secret_len, salt, salt_len, iterations, out, out_len);
                                                                                                       }
                                                                                                       uint32_t PCT_encrypt(const uint8_t *key, uint32_t key_len,
                                                                                                                            const uint8_t *nonce, const uint8_t *plain, uint32_t plain_len,
                                                                                                                            uint8_t *out) {
                                                                                                           return (uint32_t)pct_encrypt(key, key_len, nonce, plain, plain_len, out);
                                                                                                                            }
                                                                                                                            int32_t PCT_decrypt(const uint8_t *key, uint32_t key_len,
                                                                                                                                                const uint8_t *cipher, uint32_t cipher_len, uint8_t *plain) {
                                                                                                                                return (int32_t)pct_decrypt(key, key_len, cipher, cipher_len, plain);
                                                                                                                                                }
                                                                                                                                                void PCT_mac(const uint8_t *data, uint32_t data_len,
                                                                                                                                                             const uint8_t *key, uint32_t key_len,
                                                                                                                                                             uint8_t *tag, uint32_t tag_len) {
                                                                                                                                                    pct_mac(data, data_len, key, key_len, tag, tag_len);
                                                                                                                                                             }
