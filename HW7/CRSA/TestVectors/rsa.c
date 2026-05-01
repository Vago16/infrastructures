#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

#define BLOCK_SIZE 128

void strip_newline(char *s) {
    s[strcspn(s, "\r\n")] = 0;
}

int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

char *read_clean_hex_file(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        printf("Cannot open %s\n", filename);
        exit(1);
    }

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    rewind(fp);

    char *raw = malloc(size + 1);
    char *clean = malloc(size + 1);

    if (!raw || !clean) {
        printf("Memory error\n");
        exit(1);
    }

    fread(raw, 1, size, fp);
    raw[size] = '\0';
    fclose(fp);

    int j = 0;
    for (long i = 0; i < size; i++) {
        if (raw[i] != '\n' && raw[i] != '\r' && raw[i] != ' ' && raw[i] != '\t') {
            clean[j++] = raw[i];
        }
    }

    clean[j] = '\0';
    free(raw);
    return clean;
}

unsigned char *hex_to_bytes(const char *hex, size_t *out_len) {
    size_t hex_len = strlen(hex);

    if (hex_len % 2 != 0) {
        printf("Hex length is not even\n");
        exit(1);
    }

    *out_len = hex_len / 2;
    unsigned char *bytes = malloc(*out_len);

    if (!bytes) {
        printf("Memory error\n");
        exit(1);
    }

    for (size_t i = 0; i < *out_len; i++) {
        int high = hex_value(hex[2 * i]);
        int low = hex_value(hex[2 * i + 1]);

        if (high < 0 || low < 0) {
            printf("Invalid hex character\n");
            exit(1);
        }

        bytes[i] = (unsigned char)((high << 4) | low);
    }

    return bytes;
}

void write_fixed_hex(FILE *fp, const BIGNUM *num, int bytes_len) {
    unsigned char *buf = calloc(bytes_len, 1);

    if (!buf) {
        printf("Memory error\n");
        exit(1);
    }

    BN_bn2binpad(num, buf, bytes_len);

    for (int i = 0; i < bytes_len; i++) {
        fprintf(fp, "%02X", buf[i]);
    }

    free(buf);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s rsa_params.txt message.txt\n", argv[0]);
        return 1;
    }

    FILE *param_file = fopen(argv[1], "r");

    if (!param_file) {
        printf("Cannot open rsa params file\n");
        return 1;
    }

    char e_hex[5000];
    char d_hex[5000];
    char n_hex[5000];

    fgets(e_hex, sizeof(e_hex), param_file);
    fgets(d_hex, sizeof(d_hex), param_file);
    fgets(n_hex, sizeof(n_hex), param_file);

    fclose(param_file);

    strip_newline(e_hex);
    strip_newline(d_hex);
    strip_newline(n_hex);

    BIGNUM *e = NULL;
    BIGNUM *d = NULL;
    BIGNUM *n = NULL;

    BN_hex2bn(&e, e_hex);
    BN_hex2bn(&d, d_hex);
    BN_hex2bn(&n, n_hex);

    char *message_hex = read_clean_hex_file(argv[2]);

    size_t message_len = 0;
    unsigned char *message = hex_to_bytes(message_hex, &message_len);

    free(message_hex);

    if (message_len % BLOCK_SIZE != 0) {
        printf("Message byte length must be multiple of 128\n");
        return 1;
    }

    size_t blocks = message_len / BLOCK_SIZE;

    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *aggregate = BN_new();
    BN_one(aggregate);

    FILE *individual_file = fopen("individual_rsa.txt", "w");
    FILE *condensed_file = fopen("condensed_rsa.txt", "w");

    if (!individual_file || !condensed_file) {
        printf("Cannot create output files\n");
        return 1;
    }

    int rsa_bytes = BN_num_bytes(n);

    for (size_t i = 0; i < blocks; i++) {
        unsigned char hash[SHA256_DIGEST_LENGTH];

        SHA256(message + (i * BLOCK_SIZE), BLOCK_SIZE, hash);

        BIGNUM *h_bn = BN_bin2bn(hash, SHA256_DIGEST_LENGTH, NULL);
        BIGNUM *sig_i = BN_new();

        BN_mod_exp(sig_i, h_bn, d, n, ctx);

        char *sig_hex = BN_bn2hex(sig_i);
        fprintf(individual_file, "%s", sig_hex);
        OPENSSL_free(sig_hex);

        if (i != blocks - 1) {
            fprintf(individual_file, "\n");
        }

        BN_mod_mul(aggregate, aggregate, sig_i, n, ctx);

        BN_free(h_bn);
        BN_free(sig_i);
    }

    write_fixed_hex(condensed_file, aggregate, rsa_bytes);

    fclose(individual_file);
    fclose(condensed_file);

    free(message);

    BN_free(e);
    BN_free(d);
    BN_free(n);
    BN_free(aggregate);
    BN_CTX_free(ctx);

    return 0;
}
