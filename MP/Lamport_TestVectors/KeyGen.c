//Lamport Key Generation
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

/* Function Prototypes */
unsigned char* Read_File(char fileName[], int *fileLen);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);

/* ============================
            MAIN
=============================== */
int main(int argc, char *argv[]) {

    if (argc != 2) {
        printf("Usage: %s Seed.txt\n", argv[0]);
        return 1;
    }

    /* Read seed */
    int seedLen;
    unsigned char *seed = Read_File(argv[1], &seedLen);

    /* Normalize seed to 32 bytes (ChaCha20 key size) */
    unsigned char key[32] = {0};
    memcpy(key, seed, seedLen > 32 ? 32 : seedLen);

    /* Allocate SK and PK */
    unsigned char SK[2][256][32];
    unsigned char PK[2][256][32];

    /* Generate SK and PK */
    for (int j = 0; j < 256; j++) {
        for (int i = 0; i < 2; i++) {

            unsigned char nonce[16] = {0};
            nonce[0] = (unsigned char)i;
            nonce[1] = (unsigned char)j;

            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, nonce);

            unsigned char zeros[32] = {0};
            int outlen;

            EVP_EncryptUpdate(ctx, SK[i][j], &outlen, zeros, 32);
            EVP_EncryptFinal(ctx, SK[i][j], &outlen);

            EVP_CIPHER_CTX_free(ctx);

            /* PK = SHA256(SK) */
            unsigned char *hash = Hash_SHA256(SK[i][j], 32);
            memcpy(PK[i][j], hash, 32);
            free(hash);
        }
    }

    /* Write SK.txt and PK.txt */
    FILE *fsk = fopen("SK.txt", "w");
    FILE *fpk = fopen("PK.txt", "w");

    if (!fsk || !fpk) {
        printf("Error opening output files.\n");
        return 1;
    }

    char hex[65];

    for (int j = 0; j < 256; j++) {
        for (int i = 0; i < 2; i++) {

            Convert_to_Hex(hex, SK[i][j], 32);
            fprintf(fsk, "%s\n", hex);

            Convert_to_Hex(hex, PK[i][j], 32);
            fprintf(fpk, "%s\n", hex);
        }
    }

    fclose(fsk);
    fclose(fpk);

    free(seed);

    return 0;
}

/* ============================
        Read File
=============================== */
unsigned char* Read_File(char fileName[], int *fileLen)
{
    FILE *pFile = fopen(fileName, "r");
    if (pFile == NULL) {
        printf("Error opening file.\n");
        exit(0);
    }

    fseek(pFile, 0L, SEEK_END);
    int temp_size = ftell(pFile) + 1;
    fseek(pFile, 0L, SEEK_SET);

    unsigned char *output = (unsigned char*) malloc(temp_size);
    fgets((char*)output, temp_size, pFile);

    fclose(pFile);

    *fileLen = temp_size - 1;
    return output;
}

/* ============================
        Convert to Hex
=============================== */
void Convert_to_Hex(char output[], unsigned char input[], int inputlength)
{
    for (int i = 0; i < inputlength; i++) {
        sprintf(&output[2*i], "%02x", input[i]);
    }
    output[inputlength * 2] = '\0';
}

/* ============================
        SHA-256
=============================== */
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen)
{
    unsigned char *hash = malloc(SHA256_DIGEST_LENGTH);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, input, inputlen);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);

    return hash;
}

