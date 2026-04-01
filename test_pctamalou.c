#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

/* Prototypes des fonctions exportées (API) */
void PCT_hash(const uint8_t *data, uint32_t data_len, uint8_t *out, uint32_t out_len);
uint32_t PCT_encrypt(const uint8_t *key, uint32_t key_len,
                     const uint8_t *nonce, const uint8_t *plain, uint32_t plain_len,
                     uint8_t *out);
int32_t PCT_decrypt(const uint8_t *key, uint32_t key_len,
                    const uint8_t *cipher, uint32_t cipher_len, uint8_t *plain);
void PCT_mac(const uint8_t *data, uint32_t data_len,
             const uint8_t *key, uint32_t key_len,
             uint8_t *tag, uint32_t tag_len);
void PCT_kdf(const uint8_t *secret, uint32_t secret_len,
             const uint8_t *salt, uint32_t salt_len,
             uint32_t iterations, uint8_t *out, uint32_t out_len);

/* ---------- Utilitaires ---------- */
static void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
}
static int memcmp_ct(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t r = 0;
    for (size_t i = 0; i < n; i++) r |= a[i] ^ b[i];
    return r;
}

/* ---------- Tests ---------- */
int test_hash_determinism() {
    const char *msg = "Hello PCTamalou";
    uint8_t h1[64], h2[64];
    PCT_hash((uint8_t*)msg, strlen(msg), h1, 64);
    PCT_hash((uint8_t*)msg, strlen(msg), h2, 64);
    return memcmp_ct(h1, h2, 64) == 0 ? 0 : 1;
}

int test_hash_sensitive() {
    const char *msg1 = "Hello";
    const char *msg2 = "hello";
    uint8_t h1[64], h2[64];
    PCT_hash((uint8_t*)msg1, strlen(msg1), h1, 64);
    PCT_hash((uint8_t*)msg2, strlen(msg2), h2, 64);
    return memcmp_ct(h1, h2, 64) != 0 ? 0 : 1;
}

int test_avalanche() {
    const char *msg = "Test";
    uint8_t h1[64];
    PCT_hash((uint8_t*)msg, strlen(msg), h1, 64);
    uint8_t h2[64];
    // Changer un bit du message
    char msg2[5];
    memcpy(msg2, msg, 5);
    msg2[2] ^= 0x01;
    PCT_hash((uint8_t*)msg2, 5, h2, 64);
    int diff = 0;
    for (int i = 0; i < 64; i++) diff += __builtin_popcount(h1[i] ^ h2[i]);
    float percent = (diff * 100.0f) / (64*8);
    printf("Avalanche : %.1f%% bits changés\n", percent);
    return (percent > 40 && percent < 60) ? 0 : 1;
}

int test_kdf() {
    uint8_t secret[] = "my secret";
    uint8_t salt[16] = {0};
    uint8_t out1[32], out2[32];
    PCT_kdf(secret, sizeof(secret), salt, 16, 1, out1, 32);
    PCT_kdf(secret, sizeof(secret), salt, 16, 1, out2, 32);
    if (memcmp_ct(out1, out2, 32) != 0) return 1;
    // changer le sel
    salt[0] = 1;
    PCT_kdf(secret, sizeof(secret), salt, 16, 1, out2, 32);
    return (memcmp_ct(out1, out2, 32) == 0) ? 1 : 0;
}

int test_encrypt_decrypt_basic() {
    uint8_t key[32] = {0};
    uint8_t nonce[16] = {0};
    const char *plain = "Message secret";
    uint8_t cipher[256];
    uint8_t plain2[256];
    size_t clen = PCT_encrypt(key, 32, nonce, (uint8_t*)plain, strlen(plain), cipher);
    int64_t plen = PCT_decrypt(key, 32, cipher, clen, plain2);
    if (plen != (int64_t)strlen(plain)) return 1;
    return memcmp_ct((uint8_t*)plain, plain2, strlen(plain)) ? 1 : 0;
}

int test_bad_key() {
    uint8_t key1[32] = {0};
    uint8_t key2[32] = {1};
    uint8_t nonce[16] = {0};
    const char *plain = "Test";
    uint8_t cipher[256];
    uint8_t plain2[256];
    size_t clen = PCT_encrypt(key1, 32, nonce, (uint8_t*)plain, strlen(plain), cipher);
    int64_t plen = PCT_decrypt(key2, 32, cipher, clen, plain2);
    return (plen == -1) ? 0 : 1;
}

int test_tampered_cipher() {
    uint8_t key[32] = {0};
    uint8_t nonce[16] = {0};
    const char *plain = "Test";
    uint8_t cipher[256];
    size_t clen = PCT_encrypt(key, 32, nonce, (uint8_t*)plain, strlen(plain), cipher);
    cipher[clen-1] ^= 0xFF;  // altérer le tag
    uint8_t plain2[256];
    int64_t plen = PCT_decrypt(key, 32, cipher, clen, plain2);
    return (plen == -1) ? 0 : 1;
}

int test_empty_message() {
    uint8_t key[32] = {0};
    uint8_t nonce[16] = {0};
    uint8_t cipher[256];
    size_t clen = PCT_encrypt(key, 32, nonce, NULL, 0, cipher);
    uint8_t plain2[256];
    int64_t plen = PCT_decrypt(key, 32, cipher, clen, plain2);
    return (plen == 0) ? 0 : 1;
}

int test_random_4096() {
    uint8_t key[32];
    uint8_t nonce[16];
    uint8_t *plain = malloc(4096);
    uint8_t *cipher = malloc(4096 + 48);
    uint8_t *dec = malloc(4096);
    for (size_t i = 0; i < 4096; i++) plain[i] = rand() & 0xFF;
    for (int i = 0; i < 32; i++) key[i] = rand();
    for (int i = 0; i < 16; i++) nonce[i] = rand();
    size_t clen = PCT_encrypt(key, 32, nonce, plain, 4096, cipher);
    int64_t plen = PCT_decrypt(key, 32, cipher, clen, dec);
    int ok = (plen == 4096 && memcmp_ct(plain, dec, 4096) == 0);
    free(plain); free(cipher); free(dec);
    return ok ? 0 : 1;
}

int test_mac_deterministic() {
    uint8_t key[32] = {0};
    uint8_t data[] = "message";
    uint8_t tag1[32], tag2[32];
    PCT_mac(data, sizeof(data), key, 32, tag1, 32);
    PCT_mac(data, sizeof(data), key, 32, tag2, 32);
    return (memcmp_ct(tag1, tag2, 32) == 0) ? 0 : 1;
}

int test_mac_sensitive() {
    uint8_t key[32] = {0};
    uint8_t data1[] = "message";
    uint8_t data2[] = "message2";
    uint8_t tag1[32], tag2[32];
    PCT_mac(data1, sizeof(data1), key, 32, tag1, 32);
    PCT_mac(data2, sizeof(data2), key, 32, tag2, 32);
    return (memcmp_ct(tag1, tag2, 32) != 0) ? 0 : 1;
}

/* ---------- Benchmark ---------- */
void bench_hash() {
    const size_t sizes[] = {1024, 64*1024};
    const char *names[] = {"1 KB", "64 KB"};
    uint8_t *buf = malloc(64*1024);
    for (size_t i = 0; i < 64*1024; i++) buf[i] = rand() & 0xFF;
    for (int s = 0; s < 2; s++) {
        size_t len = sizes[s];
        clock_t start = clock();
        int loops = (len == 1024) ? 1000 : 16;
        for (int i = 0; i < loops; i++) {
            uint8_t hash[64];
            PCT_hash(buf, len, hash, 64);
        }
        clock_t end = clock();
        double seconds = (double)(end - start) / CLOCKS_PER_SEC;
        double mb = (double)len * loops / (1024*1024);
        printf("Hash %s : %.2f MB/s\n", names[s], mb / seconds);
    }
    free(buf);
}

void bench_encrypt() {
    const size_t sizes[] = {1024, 64*1024};
    const char *names[] = {"1 KB", "64 KB"};
    uint8_t key[32] = {0};
    uint8_t nonce[16] = {0};
    uint8_t *plain = malloc(64*1024);
    uint8_t *cipher = malloc(64*1024 + 48);
    for (size_t i = 0; i < 64*1024; i++) plain[i] = rand() & 0xFF;
    for (int s = 0; s < 2; s++) {
        size_t len = sizes[s];
        clock_t start = clock();
        int loops = (len == 1024) ? 1000 : 16;
        for (int i = 0; i < loops; i++) {
            PCT_encrypt(key, 32, nonce, plain, len, cipher);
        }
        clock_t end = clock();
        double seconds = (double)(end - start) / CLOCKS_PER_SEC;
        double mb = (double)len * loops / (1024*1024);
        printf("Encrypt %s : %.2f MB/s\n", names[s], mb / seconds);
    }
    free(plain); free(cipher);
}

void bench_kdf() {
    uint8_t secret[32] = {0};
    uint8_t salt[16] = {0};
    uint8_t out[32];
    clock_t start = clock();
    PCT_kdf(secret, 32, salt, 16, 10000, out, 32);
    clock_t end = clock();
    double seconds = (double)(end - start) / CLOCKS_PER_SEC;
    printf("KDF (10k it) : %.2f s\n", seconds);
}

/* ---------- Main ---------- */
int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "bench") == 0) {
        bench_hash();
        bench_encrypt();
        bench_kdf();
        return 0;
    }

    struct test { const char *name; int (*func)(void); } tests[] = {
        {"Hash déterministe", test_hash_determinism},
        {"Hash sensible à la casse", test_hash_sensitive},
        {"Avalanche", test_avalanche},
        {"KDF déterministe", test_kdf},
        {"Encrypt/Decrypt basique", test_encrypt_decrypt_basic},
        {"Mauvaise clé → exception MAC", test_bad_key},
        {"Ciphertext modifié → exception MAC", test_tampered_cipher},
        {"Message vide", test_empty_message},
        {"4096 octets aléatoires", test_random_4096},
        {"MAC déterministe", test_mac_deterministic},
        {"MAC sensible aux données", test_mac_sensitive},
    };
    int passed = 0, failed = 0;
    for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
        printf("%-35s ... ", tests[i].name);
        fflush(stdout);
        if (tests[i].func() == 0) {
            printf("✓\n");
            passed++;
        } else {
            printf("✗\n");
            failed++;
        }
    }
    printf("\n%d tests passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
