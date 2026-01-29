// Header files
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <openssl/evp.h>
#include <openssl/sha.h>


unsigned char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], char input[], int input_length);
void Convert_to_Hex (char output[], unsigned char input[], int inputlength);
void Show_in_Hex (char name[], unsigned char hex[], int hexlen);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);

// hex char to value
static int hexval(char c) {
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return 10 + (c - 'a');
    if ('A' <= c && c <= 'F') return 10 + (c - 'A');
    return -1;
}

// convert hex string to bytes
static unsigned char* Hex_To_Bytes(unsigned char *hex, int hex_len, int *out_len) {
    while (hex_len > 0 && isspace((unsigned char)hex[hex_len - 1])) hex_len--;

    if (hex_len % 2 != 0) {
        printf("Ciphertext hex length must be even.\n");
        exit(1);
    }

    int n = hex_len / 2;
    unsigned char *out = (unsigned char*)malloc(n);
    if (!out) { printf("malloc failed\n"); exit(1); }

    for (int i = 0; i < n; i++) {
        int hi = hexval(hex[2*i]);
        int lo = hexval(hex[2*i + 1]);
        if (hi < 0 || lo < 0) {
            printf("Invalid hex in Ciphertext.txt\n");
            exit(1);
        }
        out[i] = (unsigned char)((hi << 4) | lo);
    }

    *out_len = n;
    return out;
}

int main(int argc, char *argv[]) {

    if (argc != 2) {
        printf("Usage: %s <SharedSeedFile>\n", argv[0]);
        return 1;
    }

    // 1. Bob reads ciphertext from Ciphertext
    unsigned char *ctext_hex;
    int ctext_hex_len = 0;
    ctext_hex = Read_File("Ciphertext.txt", &ctext_hex_len);

    int ctext_len = 0;
    unsigned char *ctext = Hex_To_Bytes(ctext_hex, ctext_hex_len, &ctext_len);

    // 2. Bob reads shared seed 
    unsigned char *seed;
    int seed_len = 0;
    seed = Read_File(argv[1], &seed_len);

    if (seed_len != 32) {
        printf("SharedSeed must be exactly 32 bytes.\n");
        exit(1);
    }

    // 3. Bob generates key stream 
    unsigned char *key = PRNG(seed, (unsigned long)seed_len, (unsigned long)ctext_len);

    // 4. Bob decrypts
    unsigned char *ptext = (unsigned char*)malloc(ctext_len);
    if (!ptext) { printf("malloc failed\n"); exit(1); }

    for (int i = 0; i < ctext_len; i++) {
        ptext[i] = ctext[i] ^ key[i];
    }

    // 5. Write Plaintext.txt 
    Write_File("Plaintext.txt", (char*)ptext, ctext_len);

    // 6. Hash plaintext and write Hash.txt 
    unsigned char *hash = Hash_SHA256(ptext, (unsigned long)ctext_len);

    char hash_hex[2 * SHA256_DIGEST_LENGTH + 1];
    Convert_to_Hex(hash_hex, hash, SHA256_DIGEST_LENGTH);
    Write_File("Hash.txt", hash_hex, 2 * SHA256_DIGEST_LENGTH);

    // Cleanup
    free(ctext_hex);
    free(ctext);
    free(seed);
    free(key);
    free(ptext);
    free(hash);

    return 0;
}

/*************************************************************
                    F u n c t i o n s
**************************************************************/

/*============================
        Read from File
==============================*/
unsigned char* Read_File (char fileName[], int *fileLen)
{
    FILE *pFile = fopen(fileName, "rb");
    if (pFile == NULL) {
        printf("Error opening file: %s\n", fileName);
        exit(1);
    }

    fseek(pFile, 0L, SEEK_END);
    long sz = ftell(pFile);
    fseek(pFile, 0L, SEEK_SET);

    if (sz < 0) {
        printf("Error reading file size.\n");
        exit(1);
    }

    unsigned char *output = (unsigned char*)malloc((size_t)sz + 1);
    if (!output) { printf("malloc failed\n"); exit(1); }

    size_t n = fread(output, 1, (size_t)sz, pFile);
    fclose(pFile);

    if (n != (size_t)sz) {
        printf("Error reading file contents.\n");
        exit(1);
    }

    output[sz] = '\0';
    *fileLen = (int)sz;
    return output;
}

/*============================
        Write to File
==============================*/
void Write_File(char fileName[], char input[], int input_length)
{
    FILE *pFile = fopen(fileName,"wb");
    if (pFile == NULL){
        printf("Error opening file: %s\n", fileName);
        exit(1);
    }
    fwrite(input, 1, (size_t)input_length, pFile);
    fclose(pFile);
}

/*============================
        Showing in Hex 
==============================*/
void Show_in_Hex (char name[], unsigned char hex[], int hexlen)
{
    printf("%s: ", name);
    for (int i = 0 ; i < hexlen ; i++)
        printf("%02x", hex[i]);
    printf("\n");
}

/*============================
        Convert to Hex 
==============================*/
void Convert_to_Hex(char output[], unsigned char input[], int inputlength)
{
    for (int i=0; i<inputlength; i++){
        sprintf(&output[2*i], "%02x", input[i]);
    }
    output[2*inputlength] = '\0';
}

/*============================
        PRNG Fucntion 
==============================*/
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen)
{
    (void)seedlen;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { printf("EVP_CIPHER_CTX_new failed\n"); exit(1); }

    unsigned char *pseudoRandomNumber = (unsigned char*)malloc(prnglen);
    if (!pseudoRandomNumber) { printf("malloc failed\n"); exit(1); }

    unsigned char nonce[16] = {0};

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, seed, nonce) != 1) {
        printf("EVP_EncryptInit_ex failed\n");
        exit(1);
    }

    unsigned char *zeros = (unsigned char*)calloc(prnglen, 1);
    if (!zeros) { printf("calloc failed\n"); exit(1); }

    int outlen = 0;
    if (EVP_EncryptUpdate(ctx, pseudoRandomNumber, &outlen, zeros, (int)prnglen) != 1) {
        printf("EVP_EncryptUpdate failed\n");
        exit(1);
    }

    int finlen = 0;
    if (EVP_EncryptFinal_ex(ctx, pseudoRandomNumber + outlen, &finlen) != 1) {
        printf("EVP_EncryptFinal_ex failed\n");
        exit(1);
    }

    free(zeros);
    EVP_CIPHER_CTX_free(ctx);
    return pseudoRandomNumber;
}

/*============================
        SHA-256 Fucntion
==============================*/
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen)
{
    unsigned char *hash = (unsigned char*)malloc(SHA256_DIGEST_LENGTH);
    if (!hash) { printf("malloc failed\n"); exit(1); }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { printf("EVP_MD_CTX_new failed\n"); exit(1); }

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, input, inputlen);

    unsigned int outlen = 0;
    EVP_DigestFinal_ex(ctx, hash, &outlen);
    EVP_MD_CTX_free(ctx);

    if (outlen != SHA256_DIGEST_LENGTH) {
        printf("SHA256 length mismatch\n");
        exit(1);
    }

    return hash;
}
