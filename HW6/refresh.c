#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>

typedef struct Node {
    BIGNUM *K;
    BIGNUM *BK;
    struct Node *left;
    struct Node *right;
} Node;

BIGNUM **leafBKs;
BIGNUM **internalBKs;
int leafIndex = 0;
int internalIndex = 0;

char *read_file(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        printf("Error opening file: %s\n", filename);
        exit(1);
    }

    char *buffer = (char *)malloc(4096);
    if (!fgets(buffer, 4096, fp)) {
        printf("Error reading file: %s\n", filename);
        fclose(fp);
        exit(1);
    }

    buffer[strcspn(buffer, "\r\n")] = '\0';
    fclose(fp);
    return buffer;
}

char **read_lines(const char *filename, int *count) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        printf("Error opening file: %s\n", filename);
        exit(1);
    }

    char **lines = NULL;
    char buffer[4096];
    int n = 0;

    while (fgets(buffer, sizeof(buffer), fp)) {
        buffer[strcspn(buffer, "\r\n")] = '\0';
        lines = realloc(lines, (n + 1) * sizeof(char *));
        lines[n] = strdup(buffer);
        n++;
    }

    fclose(fp);
    *count = n;
    return lines;
}

Node *build_tree(BIGNUM **secrets, int n, BIGNUM *g, BIGNUM *p, BN_CTX *ctx) {
    Node *node = (Node *)malloc(sizeof(Node));
    node->left = NULL;
    node->right = NULL;

    if (n == 1) {
        node->K = BN_dup(secrets[0]);
        node->BK = BN_new();
        BN_mod_exp(node->BK, g, node->K, p, ctx);

        leafBKs[leafIndex++] = BN_dup(node->BK);
        return node;
    }

    int leftCount = (n + 1) / 2;
    int rightCount = n / 2;

    node->left = build_tree(secrets, leftCount, g, p, ctx);
    node->right = build_tree(secrets + leftCount, rightCount, g, p, ctx);

    node->K = BN_new();
    BN_mod_exp(node->K, node->left->BK, node->right->K, p, ctx);

    node->BK = BN_new();
    BN_mod_exp(node->BK, g, node->K, p, ctx);

    internalBKs[internalIndex++] = BN_dup(node->BK);

    return node;
}

int main(int argc, char *argv[]) {
    if (argc != 6) {
        printf("Usage: ./Refresh params_p.txt params_g.txt member_secrets.txt member_index.txt new_secret.txt\n");
        return 1;
    }

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        printf("Error creating BN_CTX\n");
        return 1;
    }

    char *pStr = read_file(argv[1]);
    char *gStr = read_file(argv[2]);

    BIGNUM *p = NULL;
    BIGNUM *g = NULL;
    BN_hex2bn(&p, pStr);
    BN_hex2bn(&g, gStr);

    int count = 0;
    char **secretLines = read_lines(argv[3], &count);

    if (count <= 0) {
        printf("No secrets found\n");
        return 1;
    }

    BIGNUM **secrets = (BIGNUM **)malloc(count * sizeof(BIGNUM *));
    for (int i = 0; i < count; i++) {
        secrets[i] = NULL;
        BN_hex2bn(&secrets[i], secretLines[i]);
    }

    int idx = atoi(read_file(argv[4]));

    if (idx < 0 || idx >= count) {
        printf("Invalid refresh index\n");
        return 1;
    }

    char *newSecretStr = read_file(argv[5]);
    BIGNUM *newSecret = NULL;
    BN_hex2bn(&newSecret, newSecretStr);

    BIGNUM **newSecrets = (BIGNUM **)malloc(count * sizeof(BIGNUM *));
    for (int i = 0; i < count; i++) {
        if (i == idx) {
            newSecrets[i] = BN_dup(newSecret);
        } else {
            newSecrets[i] = BN_dup(secrets[i]);
        }
    }

    leafBKs = (BIGNUM **)malloc(count * sizeof(BIGNUM *));
    internalBKs = (BIGNUM **)malloc(count * sizeof(BIGNUM *));
    leafIndex = 0;
    internalIndex = 0;

    Node *root = build_tree(newSecrets, count, g, p, ctx);

    FILE *groupFile = fopen("group_key_refresh.txt", "w");
    if (!groupFile) {
        printf("Error writing group_key_refresh.txt\n");
        return 1;
    }

    char *groupKeyHex = BN_bn2hex(root->K);
    fprintf(groupFile, "%s", groupKeyHex);
    fclose(groupFile);

    FILE *blindFile = fopen("blinded_keys_refresh.txt", "w");
    if (!blindFile) {
        printf("Error writing blinded_keys_refresh.txt\n");
        return 1;
    }

    for (int i = 0; i < leafIndex; i++) {
        char *hex = BN_bn2hex(leafBKs[i]);
        fprintf(blindFile, "%s\n", hex);
    }

    for (int i = 0; i < internalIndex; i++) {
        char *hex = BN_bn2hex(internalBKs[i]);
        fprintf(blindFile, "%s\n", hex);
    }

    fclose(blindFile);

    return 0;
}