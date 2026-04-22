#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define HASH_LEN 32
#define SEED_LEN 30

/* Try opening file from current dir OR TestVectors folder */
static FILE *open_seed_file(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (fp) return fp;

    char alt[512];
    snprintf(alt, sizeof(alt), "Hors_TestVectors/TestVectors/%s", filename);
    fp = fopen(alt, "rb");
    if (fp) return fp;

    return NULL;
}

/* Read seed (30 bytes exactly) */
static int read_seed(const char *filename, unsigned char seed[SEED_LEN]) {
    FILE *fp = open_seed_file(filename);
    if (!fp) {
        perror("fopen seed");
        return 0;
    }

    unsigned char buf[128];
    size_t n = fread(buf, 1, sizeof(buf), fp);
    fclose(fp);

    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) {
        n--;
    }

    if (n != SEED_LEN) {
        fprintf(stderr, "Seed must be exactly %d bytes, got %zu\n", SEED_LEN, n);
        return 0;
    }

    memcpy(seed, buf, SEED_LEN);
    return 1;
}

/* Convert bytes to hex */
static void bytes_to_hex(const unsigned char *in, size_t len, char *out) {
    static const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2*i]     = hex[(in[i] >> 4) & 0xF];
        out[2*i + 1] = hex[in[i] & 0xF];
    }
    out[2*len] = '\0';
}

/* Check power of 2 */
static int is_power_of_two(int x) {
    return x > 0 && (x & (x - 1)) == 0;
}

/*
 * ✅ CORRECT PRNG
 * key = seed || i (2 bytes)
 * nonce = all zero
 */
static int generate_sk(const unsigned char seed[SEED_LEN], int i, unsigned char out[HASH_LEN]) {
    unsigned char key[32] = {0};
    unsigned char nonce[16] = {0};
    unsigned char zeros[HASH_LEN] = {0};
    int outlen1 = 0, outlen2 = 0;

    memcpy(key, seed, SEED_LEN);

    /* append i as 2 bytes LITTLE ENDIAN */
    key[30] = (unsigned char)(i & 0xFF);
    key[31] = (unsigned char)((i >> 8) & 0xFF);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (EVP_EncryptUpdate(ctx, out, &outlen1, zeros, HASH_LEN) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (EVP_EncryptFinal_ex(ctx, out + outlen1, &outlen2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    EVP_CIPHER_CTX_free(ctx);
    return (outlen1 + outlen2) == HASH_LEN;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s Seed.txt t\n", argv[0]);
        return 1;
    }

    const char *seed_file = argv[1];
    int t = atoi(argv[2]);

    if (!is_power_of_two(t) || t < 128 || t > 1024) {
        fprintf(stderr, "t must be power of 2 between 128 and 1024\n");
        return 1;
    }

    unsigned char seed[SEED_LEN];
    if (!read_seed(seed_file, seed)) return 1;

    FILE *sk_fp = fopen("SK.txt", "w");
    FILE *pk_fp = fopen("PK.txt", "w");

    if (!sk_fp || !pk_fp) {
        perror("output files");
        return 1;
    }

    for (int i = 0; i < t; i++) {
        unsigned char sk[HASH_LEN];
        unsigned char pk[HASH_LEN];
        char hexbuf[2*HASH_LEN + 1];

        if (!generate_sk(seed, i, sk)) {
            fclose(sk_fp);
            fclose(pk_fp);
            return 1;
        }

        SHA256(sk, HASH_LEN, pk);

        bytes_to_hex(sk, HASH_LEN, hexbuf);
        fprintf(sk_fp, "%s", hexbuf);
        if (i != t - 1) fprintf(sk_fp, "\n");

        bytes_to_hex(pk, HASH_LEN, hexbuf);
        fprintf(pk_fp, "%s", hexbuf);
        if (i != t - 1) fprintf(pk_fp, "\n");
    }

    fclose(sk_fp);
    fclose(pk_fp);
    return 0;
}