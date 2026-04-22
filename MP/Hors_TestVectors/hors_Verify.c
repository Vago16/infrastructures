#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#define HASH_LEN 32
#define MAX_T 1024
#define MAX_K 256

static unsigned char PK[MAX_T][HASH_LEN];
static unsigned char SIG[MAX_K][HASH_LEN];

static FILE *open_message_file(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (fp) return fp;

    char alt_path[512];
    snprintf(alt_path, sizeof(alt_path), "Hors_TestVectors/TestVectors/%s", filename);
    fp = fopen(alt_path, "rb");
    if (fp) return fp;

    return NULL;
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_to_bytes(const char *hex, unsigned char *out, int out_len) {
    int len = (int)strlen(hex);
    if (len != out_len * 2) return 0;

    for (int i = 0; i < out_len; i++) {
        int hi = hex_val(hex[2 * i]);
        int lo = hex_val(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

static int read_pk(int t) {
    FILE *fp = fopen("PK.txt", "r");
    if (!fp) {
        perror("fopen PK.txt");
        return 0;
    }

    char line[128];
    for (int i = 0; i < t; i++) {
        if (!fgets(line, sizeof(line), fp)) {
            fclose(fp);
            fprintf(stderr, "Failed reading PK line %d\n", i);
            return 0;
        }
        line[strcspn(line, "\r\n")] = '\0';
        if (!hex_to_bytes(line, PK[i], HASH_LEN)) {
            fclose(fp);
            fprintf(stderr, "Invalid PK hex at line %d\n", i);
            return 0;
        }
    }

    fclose(fp);
    return 1;
}

static int read_sig(int k) {
    FILE *fp = fopen("Signature.txt", "r");
    if (!fp) {
        perror("fopen Signature.txt");
        return 0;
    }

    char line[128];
    for (int i = 0; i < k; i++) {
        if (!fgets(line, sizeof(line), fp)) {
            fclose(fp);
            fprintf(stderr, "Failed reading signature line %d\n", i);
            return 0;
        }
        line[strcspn(line, "\r\n")] = '\0';
        if (!hex_to_bytes(line, SIG[i], HASH_LEN)) {
            fclose(fp);
            fprintf(stderr, "Invalid signature hex at line %d\n", i);
            return 0;
        }
    }

    fclose(fp);
    return 1;
}

static int log2_int(int x) {
    int r = 0;
    while (x > 1) {
        x >>= 1;
        r++;
    }
    return r;
}

static int get_hors_index(const unsigned char *digest, int start_bit, int bit_len) {
    int value = 0;
    for (int i = 0; i < bit_len; i++) {
        int bit_pos = start_bit + (bit_len - 1 - i);
        int byte_index = bit_pos / 8;
        int bit_index = bit_pos % 8;   /* LSB-first inside byte */
        int bit = (digest[byte_index] >> bit_index) & 1;
        value = (value << 1) | bit;
    }
    return value;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s Message.txt t k\n", argv[0]);
        return 1;
    }

    const char *message_file = argv[1];
    int t = atoi(argv[2]);
    int k = atoi(argv[3]);

    if (t <= 0 || t > MAX_T || k <= 0 || k > MAX_K) {
        fprintf(stderr, "Invalid t or k\n");
        return 1;
    }

    if (!read_pk(t) || !read_sig(k)) {
        return 1;
    }

    FILE *fp = open_message_file(message_file);
    if (!fp) {
        perror("fopen message");
        return 1;
    }

    unsigned char msg[8192];
    size_t msg_len = fread(msg, 1, sizeof(msg), fp);
    fclose(fp);

    unsigned char digest[HASH_LEN];
    SHA256(msg, msg_len, digest);

    int bits = log2_int(t);
    if (k * bits > 256) {
        fprintf(stderr, "k * log2(t) exceeds 256 bits\n");
        return 1;
    }

    int valid = 1;

    for (int i = 0; i < k; i++) {
        int idx = get_hors_index(digest, i * bits, bits);
        if (idx < 0 || idx >= t) {
            valid = 0;
            break;
        }

        unsigned char hash[HASH_LEN];
        SHA256(SIG[i], HASH_LEN, hash);

        if (memcmp(hash, PK[idx], HASH_LEN) != 0) {
            valid = 0;
            break;
        }
    }

    FILE *out = fopen("Verification.txt", "w");
    if (!out) {
        perror("fopen Verification.txt");
        return 1;
    }

    if (valid) {
        fprintf(out, "Signature is Valid");
    } else {
        fprintf(out, "Signature is Invalid");
    }

    fclose(out);
    return 0;
}