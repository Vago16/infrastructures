#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

#define SEED_LEN 32
#define KEY_LEN  32
#define HLEN     32
#define MSG_LEN  1024
#define IV_LEN   16
#define MAX_LINES 2048

static void die(const char *m) {
    fprintf(stderr, "Error: %s\n", m);
    exit(1);
}

static int hexval(char c) {
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return c - 'a' + 10;
    if ('A' <= c && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Converts a hex string to bytes.
// Returns number of bytes written.
static size_t hex_to_bytes(const char *hexline, unsigned char *out, size_t out_max) {
    size_t len = strlen(hexline);

    while (len > 0 && (hexline[len-1] == '\n' || hexline[len-1] == '\r' ||
                       hexline[len-1] == ' '  || hexline[len-1] == '\t')) {
        len--;
    }

    if (len % 2 != 0) die("hex string has odd length");
    size_t out_len = len / 2;
    if (out_len > out_max) die("hex decoded length too big");

    for (size_t i = 0; i < out_len; i++) {
        int hi = hexval(hexline[2*i]);
        int lo = hexval(hexline[2*i + 1]);
        if (hi < 0 || lo < 0) die("invalid hex character");
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return out_len;
}

static void sha256_bytes(const unsigned char *in, size_t inlen, unsigned char out[32]) {
    SHA256(in, inlen, out);
}

static void hmac_sha256(const unsigned char key[32], const unsigned char *data, size_t dlen,
                        unsigned char out[32]) {
    unsigned int outlen = 0;
    unsigned char *res = HMAC(EVP_sha256(), key, 32, data, dlen, out, &outlen);
    if (!res || outlen != 32) die("HMAC failed");
}


static void chacha20_prng_32(const unsigned char seed[32], unsigned char out[32]) {
    // ChaCha20 encryption of 32 zero bytes that yields 32 bytes of keystream
    unsigned char nonce[16] = {0};   
    unsigned char zeros[32] = {0};
    int len1 = 0, len2 = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) die("EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, seed, nonce) != 1)
        die("ChaCha20 init failed");

    if (EVP_EncryptUpdate(ctx, out, &len1, zeros, 32) != 1)
        die("ChaCha20 update failed");

    if (EVP_EncryptFinal_ex(ctx, out + len1, &len2) != 1)
        die("ChaCha20 final failed");

    EVP_CIPHER_CTX_free(ctx);

    if (len1 + len2 != 32) die("ChaCha20 produced wrong length");
}

static int aes256ctr_decrypt(const unsigned char key[32], const unsigned char iv[16],
                             const unsigned char *ct, size_t ctlen,
                             unsigned char *pt) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    int len = 0, outlen = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (EVP_DecryptUpdate(ctx, pt, &len, ct, (int)ctlen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    outlen = len;

    if (EVP_DecryptFinal_ex(ctx, pt + outlen, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    outlen += len;

    EVP_CIPHER_CTX_free(ctx);
    return outlen;
}

// SharedSeed file
static void read_seed(const char *path, unsigned char seed[32]) {
    FILE *f = fopen(path, "rb");
    if (!f) die("cannot open SharedSeed file");

    unsigned char buf[256];
    size_t n = fread(buf, 1, sizeof(buf)-1, f);
    fclose(f);
    if (n == 0) die("SharedSeed file empty");
    buf[n] = 0;

    // Strip whitespace into tmp
    char tmp[256];
    size_t j = 0;
    for (size_t i = 0; i < n && j < sizeof(tmp)-1; i++) {
        if (buf[i] != '\n' && buf[i] != '\r' && buf[i] != ' ' && buf[i] != '\t')
            tmp[j++] = (char)buf[i];
    }
    tmp[j] = 0;

    if (j == 64) {
        size_t got = hex_to_bytes(tmp, seed, 32);
        if (got != 32) die("SharedSeed hex is not 32 bytes");
        return;
    }

    if (n < 32) die("SharedSeed raw length < 32");
    memcpy(seed, buf, 32);
}

static size_t read_ciphertexts_hex_lines(const char *path, unsigned char C[MAX_LINES][MSG_LEN]) {
    FILE *f = fopen(path, "r");
    if (!f) die("cannot open Ciphertexts file");

    char line[8192];
    size_t count = 0;

    while (fgets(line, sizeof(line), f)) {
        // skip empty
        size_t k = 0;
        while (line[k] == ' ' || line[k] == '\t' || line[k] == '\r' || line[k] == '\n') k++;
        if (line[k] == 0) continue;

        if (count >= MAX_LINES) die("too many ciphertext lines");

        unsigned char tmp[MSG_LEN];
        size_t got = hex_to_bytes(line, tmp, MSG_LEN);
        if (got != MSG_LEN) die("ciphertext line is not 1024 bytes (decoded)");
        memcpy(C[count], tmp, MSG_LEN);
        count++;
    }
    fclose(f);

    if (count == 0) die("Ciphertexts file had 0 ciphertexts");
    return count;
}

static void read_agg_hex(const char *path, unsigned char agg[32]) {
    FILE *f = fopen(path, "r");
    if (!f) die("cannot open AggregatedHMAC file");

    char line[1024];
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        die("AggregatedHMAC file empty");
    }
    fclose(f);

    size_t got = hex_to_bytes(line, agg, 32);
    if (got != 32) die("AggregatedHMAC decoded length != 32");
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s SharedSeed.txt Ciphertexts.txt AggregatedHMAC.txt\n", argv[0]);
        return 1;
    }

    const char *seed_path = argv[1];
    const char *ct_path   = argv[2];
    const char *agg_path  = argv[3];

    unsigned char seed[32];
    read_seed(seed_path, seed);

    // k1
    unsigned char k[32];
    chacha20_prng_32(seed, k);

    //  ciphertexts
    unsigned char C[MAX_LINES][MSG_LEN];
    size_t n = read_ciphertexts_hex_lines(ct_path, C);

    // received aggregate
    unsigned char recvAgg[32];
    read_agg_hex(agg_path, recvAgg);

    // Store keys for decryption if verification succeeds
    unsigned char keys[MAX_LINES][32];

    unsigned char agg[32];
    int agg_init = 0;

    for (size_t i = 0; i < n; i++) {
        memcpy(keys[i], k, 32); 

        unsigned char Si[32];
        hmac_sha256(k, C[i], MSG_LEN, Si);

        if (!agg_init) {
            // S1,1 = H(S1)
            sha256_bytes(Si, 32, agg);
            agg_init = 1;
        } else {
            // S1,i = H(S1,i-1 || Si)
            unsigned char buf[64];
            memcpy(buf, agg, 32);
            memcpy(buf + 32, Si, 32);
            sha256_bytes(buf, 64, agg);
        }

        // k_{i+1} = H(k_i)
        sha256_bytes(k, 32, k);
    }

    
    if (CRYPTO_memcmp(agg, recvAgg, 32) != 0) {
        fprintf(stderr, "Verification FAILED: aggregated HMAC mismatch. Not decrypting.\n");
        return 2;
    }

    fprintf(stderr, "Verification OK. Decrypting...\n");

    unsigned char IV[16] = "abcdefghijklmnop";

    FILE *out = fopen("Plaintexts.txt", "wb");
    if (!out) die("cannot create Plaintexts.txt");

    for (size_t i = 0; i < n; i++) {
        unsigned char pt[MSG_LEN];
        int ptlen = aes256ctr_decrypt(keys[i], IV, C[i], MSG_LEN, pt);
        if (ptlen != MSG_LEN) die("AES-CTR produced wrong length");

        fwrite(pt, 1, MSG_LEN, out);
        if (i < n - 1)
            fputc('\n', out);
    }

    fclose(out);
    return 0;
}