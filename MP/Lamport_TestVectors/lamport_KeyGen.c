//Lamport Key Generation
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

//function prototypes
unsigned char* Read_File(char fileName[], int *fileLen);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s Seed.txt\n", argv[0]);
        return 1;
    }

    //1. CA reads the seed from a file named ”Seed.txt”.
    int seedLen;
    unsigned char *seed = Read_File(argv[1], &seedLen);

    unsigned char SK[2][256][32];
    unsigned char PK[2][256][32];

    //2/3. Generate SK
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 256; j++) {

            //key = seed || i || j, padded to 32 bytes with zeros, i and j are single bits as seed is 30 bits
            unsigned char key[32] = {0};
            memcpy(key, seed, seedLen);
            key[seedLen]     = (unsigned char)i;
            key[seedLen + 1] = (unsigned char)j;

            //nonce: all zeros
            unsigned char nonce[16] = {0};

            //encrypt 32 zero bytes to get SK[i][j]
            unsigned char zeros[32] = {0};
            unsigned char out[32];
            int outlen;

            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, nonce);
            EVP_EncryptUpdate(ctx, out, &outlen, zeros, 32);
            EVP_CIPHER_CTX_free(ctx);

            memcpy(SK[i][j], out, 32);

            unsigned char *pk = Hash_SHA256(out, 32);
            memcpy(PK[i][j], pk, 32);
            free(pk);
        }
    }

    //4/5. Write SK.txt and PK.txt in column-wise order: (0,0),(1,0),(0,1),(1,1),...
    FILE *fsk = fopen("SK.txt", "wb");
    FILE *fpk = fopen("PK.txt", "wb");

    char hex[65];
    for (int j = 0; j < 256; j++) {
        for (int i = 0; i < 2; i++) {
            Convert_to_Hex(hex, SK[i][j], 32);
            if (j == 255 && i == 1)
                fprintf(fsk, "%s", hex);      // no newline on last line
            else
                fprintf(fsk, "%s\n", hex);

            Convert_to_Hex(hex, PK[i][j], 32);
            if (j == 255 && i == 1)
                fprintf(fpk, "%s", hex);      // no newline on last line
            else
                fprintf(fpk, "%s\n", hex);
        }
    }

    fclose(fsk);
    fclose(fpk);

    //cleanup
    free(seed);
    return 0;
}

/* ========================= */
unsigned char* Read_File(char fileName[], int *fileLen)
{
    FILE *pFile = fopen(fileName, "rb");
    if (!pFile) exit(1);
    fseek(pFile, 0, SEEK_END);
    long size = ftell(pFile);
    fseek(pFile, 0, SEEK_SET);
    unsigned char *output = malloc(size + 1);
    fread(output, 1, size, pFile);
    fclose(pFile);
    output[size] = '\0';
    *fileLen = size;
    return output;
}

/* ========================= */
void Convert_to_Hex(char output[], unsigned char input[], int inputlength)
{
    for (int i = 0; i < inputlength; i++)
        sprintf(&output[2*i], "%02x", input[i]);
    output[inputlength * 2] = '\0';
}

/* ========================= */
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