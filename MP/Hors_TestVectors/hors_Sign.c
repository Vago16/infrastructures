#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#define HASH_LEN 32
#define MAX_T 1024

static unsigned char SK[MAX_T][HASH_LEN];

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

static int read_sk(int t) {
    FILE *fp = fopen("SK.txt", "r");
    if (!fp) {
        perror("fopen SK.txt");
        return 0;
    }

    char line[128];
    for (int i = 0; i < t; i++) {
        if (!fgets(line, sizeof(line), fp)) {
            fclose(fp);
            fprintf(stderr, "Failed reading SK line %d\n", i);
            return 0;
        }
        line[strcspn(line, "\r\n")] = '\0';
        if (!hex_to_bytes(line, SK[i], HASH_LEN)) {
            fclose(fp);
            fprintf(stderr, "Invalid SK hex at line %d\n", i);
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

/*
 * Exact rule from the vectors:
 * - digest bits are read LSB-first inside each byte
 * - no global offset
 * - chunk order is normal
 * - bits inside each chunk are reversed before converting to int
 *
 * Equivalent direct implementation:
 *   read chunk bits from (start_bit + bit_len - 1) down to start_bit
 *   using bit_index = bit_pos % 8
 */
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

    if (t <= 0 || t > MAX_T || k <= 0) {
        fprintf(stderr, "Invalid t or k\n");
        return 1;
    }

    if (!read_sk(t)) {
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

    FILE *out = fopen("Signature.txt", "w");
    if (!out) {
        perror("fopen Signature.txt");
        return 1;
    }

    for (int i = 0; i < k; i++) {
        int idx = get_hors_index(digest, i * bits, bits);
        if (idx < 0 || idx >= t) {
            fclose(out);
            fprintf(stderr, "Index out of range: %d\n", idx);
            return 1;
        }

        for (int j = 0; j < HASH_LEN; j++) {
            fprintf(out, "%02x", SK[idx][j]);
        }
        if (i != k - 1) fprintf(out, "\n");
    }

    fclose(out);
    return 0;
}