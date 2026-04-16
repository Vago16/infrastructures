#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

//function prototypes
char* Read_File(const char *filename, int *length);
int Write_File(const char *filename, const char *data);

//struct for tree nodes
typedef struct Node {
    BIGNUM *K;
    BIGNUM *BK;
    struct Node *left;
    struct Node *right;
} Node;

//helper functions
void to_upper(char *s) {
    for (int i = 0; s[i]; i++) {
        if (s[i] >= 'a' && s[i] <= 'f')
            s[i] -= 32;
    }
}

BIGNUM* sha256_to_bn(const char *input) {
    unsigned char hash[32];
    SHA256((unsigned char*)input, strlen(input), hash);
    return BN_bin2bn(hash, 32, NULL);
}

void compute_BK(BIGNUM *BK, BIGNUM *g, BIGNUM *K, BIGNUM *p, BN_CTX *ctx) {
    BN_mod_exp(BK, g, K, p, ctx);
}

/* BUILD TREE- balanced but left-heavy split */
Node* build_tree(BIGNUM **secrets, int start, int end,
                 BIGNUM *g, BIGNUM *p, BN_CTX *ctx) {

    int n = end - start;

    Node *node = malloc(sizeof(Node));
    node->left = node->right = NULL;

    /* leaf */
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

    node->K = BN_new();
    BN_mod_exp(node->K,
               node->left->BK,
               node->right->K,
               p,
               ctx);

    node->BK = BN_new();
    compute_BK(node->BK, g, node->K, p, ctx);

    return node;
}

/* Write leaf blinded keys, left to right */
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

/* Write nternal node blinded keys in post-order (children before parent) */
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
    //if wrong number of arguments passed
    if (argc < 5) {
        printf("Wrong number of arguments passed\n");
        return 1;
    }
    //1. Read DH parameters p and g from files.
    BN_CTX *ctx = BN_CTX_new();

    //read p
    int len;
    char *p_str = Read_File(argv[1], &len);
    BIGNUM *p = NULL;
    BN_hex2bn(&p, p_str);
    free(p_str);

    //read g
    char *g_str = Read_File(argv[2], &len);
    BIGNUM *g = NULL;
    BN_hex2bn(&g, g_str);
    free(g_str);

    int n = argc - 3;

    //2. Read member seed files (one per member). Derive each member’s secret key via SHA-256.
    BIGNUM **secrets = malloc(n * sizeof(BIGNUM*));

    for (int i = 0; i < n; i++) {
        char *seed = Read_File(argv[i + 3], &len);

        secrets[i] = sha256_to_bn(seed);

        free(seed);
    }

    //3. Build the TGDH key tree using left-heavy balanced splitting. (both steps 3 and 4 are done at the same time)
    //4. Compute all internal node keys bottom-up using Kparent = BK Kright left mod p.
    Node *root = build_tree(secrets, 0, n, g, p, ctx);

    //5. Write the group key (hex) to “group key setup.txt”.
    char *group_hex = BN_bn2hex(root->K);
    to_upper(group_hex);

    Write_File("group_key_setup.txt", group_hex);
    OPENSSL_free(group_hex);

    //6. Write all blinded keys (hex, one per line) to “blinded keys setup.txt”:
        //• First: leaf blinded keys, left to right
        //• Then: internal node blinded keys in post-order (children before parent)

    FILE *f = fopen("blinded_keys_setup.txt", "w");

    write_leaves(root, f);
    write_internal(root, f);
    fclose(f);

     BN_CTX_free(ctx);

    return 0;
}

//from RequiredFunctionsTGDH.c
/*
   File I/O Functions  
 */

/* Read entire file as string, strip trailing whitespace */
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
    if (!buffer) { fclose(file); return NULL; }
    size_t read_size = fread(buffer, 1, file_size, file);
    buffer[read_size] = '\0';
    while (read_size > 0 && (buffer[read_size-1] == '\n' || 
           buffer[read_size-1] == '\r' || buffer[read_size-1] == ' '))
        buffer[--read_size] = '\0';
    *length = (int)read_size;
    fclose(file);
    return buffer;
}

/* Write string to file */
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

/* Read an integer from a file */
int Read_Int_From_File(const char *filename) {
    int length;
    char *str = Read_File(filename, &length);
    if (!str) return -1;
    int value = atoi(str);
    free(str);
    return value;
}

/* 
Read multi-line file into array of strings (one per line).
Returns number of lines read. Caller must free each line and the array
*/
int Read_Lines(const char *filename, char ***lines_out) {
    FILE *f = fopen(filename, "r");
    if (!f) { fprintf(stderr, "Error: Cannot open %s\n", filename); return 0; }
    
    char **lines = NULL;
    int count = 0;
    char buf[1024];
    
    while (fgets(buf, sizeof(buf), f)) {
        /* Strip newline/whitespace */
        int len = strlen(buf);
        while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r' || buf[len-1] == ' '))
            buf[--len] = '\0';
        if (len == 0) continue;  /* skip blank lines */
        
        lines = realloc(lines, (count + 1) * sizeof(char*));
        lines[count] = strdup(buf);
        count++;
    }
    
    fclose(f);
    *lines_out = lines;
    return count;
}


/* 
   Hex Conversion Functions  
*/

/* Print data as hex */
void Print_Hex(const char *label, const unsigned char *data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

/* Convert byte array to hex string */
void Bytes_to_Hex(char *output, const unsigned char *input, int inputlength) {
    for (int i = 0; i < inputlength; i++)
        sprintf(&output[2*i], "%02x", input[i]);
    output[inputlength * 2] = '\0';
}
