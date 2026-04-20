#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

// function prototypes
char* Read_File(const char *filename, int *length);
int Write_File(const char *filename, const char *data);

// struct for tree nodes
typedef struct Node {
    BIGNUM *K;
    BIGNUM *BK;
    struct Node *left;
    struct Node *right;
} Node;

// helper functions
void to_upper(char *s) {
    for (int i = 0; s[i]; i++) {
        if (s[i] >= 'a' && s[i] <= 'f')
            s[i] -= 32;
    }
}

BIGNUM* sha256_to_bn(const char *input) {
    if (!input) {
        printf("Error: NULL input to SHA256\n");
        exit(1);
    }

    unsigned char hash[32];
    SHA256((unsigned char*)input, strlen(input), hash);
    return BN_bin2bn(hash, 32, NULL);
}

void compute_BK(BIGNUM *BK, BIGNUM *g, BIGNUM *K, BIGNUM *p, BN_CTX *ctx) {
    BN_mod_exp(BK, g, K, p, ctx);
}

/* build tree with left-heavy split */
Node* build_tree(BIGNUM **secrets, int start, int end,
                 BIGNUM *g, BIGNUM *p, BN_CTX *ctx) {
    int n = end - start;

    Node *node = malloc(sizeof(Node));
    node->left = NULL;
    node->right = NULL;

    // leaf
    if (n == 1) {
        node->K = BN_dup(secrets[start]);
        node->BK = BN_new();
        compute_BK(node->BK, g, node->K, p, ctx);
        return node;
    }

    int left_size = (n + 1) / 2;
    int mid = start + left_size;

    node->left = build_tree(secrets, start, mid, g, p, ctx);
    node->right = build_tree(secrets, mid, end, g, p, ctx);

    // Kparent = (BK_left ^ K_right) mod p
    node->K = BN_new();
    BN_mod_exp(node->K, node->left->BK, node->right->K, p, ctx);

    node->BK = BN_new();
    compute_BK(node->BK, g, node->K, p, ctx);

    return node;
}

/* write leaf blinded keys, left to right */
void write_leaves(Node *node, FILE *f) {
    if (!node) return;

    if (!node->left && !node->right) {
        char *hex = BN_bn2hex(node->BK);
        to_upper(hex);
        fprintf(f, "%s\n", hex);
        OPENSSL_free(hex);
        return;
    }

    write_leaves(node->left, f);
    write_leaves(node->right, f);
}

/* write internal blinded keys in post-order */
void write_internal(Node *node, FILE *f) {
    if (!node || (!node->left && !node->right)) return;

    write_internal(node->left, f);
    write_internal(node->right, f);

    char *hex = BN_bn2hex(node->BK);
    to_upper(hex);
    fprintf(f, "%s\n", hex);
    OPENSSL_free(hex);
}

int main(int argc, char *argv[]) {
    if (argc != 7) {
        printf("Usage: ./Setup p g seed0 seed1 seed2 seed3\n");
        return 1;
    }


    BN_CTX *ctx = BN_CTX_new();
    int len;

    // read p
    char *p_str = Read_File(argv[1], &len);
    if (!p_str) return 1;

    if (!p_str) return 1;

    BIGNUM *p = NULL;
    BN_hex2bn(&p, p_str);
    free(p_str);

    // read g
    char *g_str = Read_File(argv[2], &len);
    if (!g_str) return 1;

    if (!g_str) return 1;

    BIGNUM *g = NULL;
    BN_hex2bn(&g, g_str);
    free(g_str);

    if (!p || !g) {
        printf("Error reading p or g\n");
        return 1;
    }

    int n = 4;
    BIGNUM **secrets = malloc(n * sizeof(BIGNUM*));

    // read seeds and hash them to secrets
    for (int i = 0; i < n; i++) {
        char *seed = Read_File(argv[i + 3], &len);

        if (!seed) {
            fprintf(stderr, "Failed reading seed %s\n", argv[i + 3]);
            return 1;
        }

        if (!seed) {
            fprintf(stderr, "Failed reading seed %s\n", argv[i + 3]);
            return 1;
        }

        secrets[i] = sha256_to_bn(seed);
        free(seed);
    }

    // build tree
    Node *root = build_tree(secrets, 0, n, g, p, ctx);

    // write group key
    char *group_hex = BN_bn2hex(root->K);
    to_upper(group_hex);
    Write_File("group_key_setup.txt", group_hex);
    OPENSSL_free(group_hex);

    // write blinded keys
    FILE *f = fopen("blinded_keys_setup.txt", "w");
    if (!f) return 1;
    if (!f) return 1;

    write_leaves(root, f);
    write_internal(root, f);

    fclose(f);

    BN_CTX_free(ctx);
    return 0;
}

/* ==========================
   provided helper functions
   ========================== */

char* Read_File(const char *filename, int *length) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *buffer = (char*)malloc(file_size + 1);
    if (!buffer) {
        fclose(file);
        return NULL;
    }

    size_t read_size = fread(buffer, 1, file_size, file);
    buffer[read_size] = '\0';

    while (read_size > 0 &&
          (buffer[read_size - 1] == '\n' ||
           buffer[read_size - 1] == '\r' ||
           buffer[read_size - 1] == ' ')) {
        buffer[--read_size] = '\0';
    }

    *length = (int)read_size;
    fclose(file);
    return buffer;
}

int Write_File(const char *filename, const char *data) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file %s for writing\n", filename);
        return -1;
    }

    fprintf(file, "%s", data);
    fclose(file);
    return 0;
}