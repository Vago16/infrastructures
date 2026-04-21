//Lamport Verify
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

//helper functions
unsigned char* Read_File(char fileName[], int *fileLen);
int Hex_To_Bytes(unsigned char output[], char input[], int inputLenBytes);

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s Message.txt\n", argv[0]);
        return 1;
    }

    //1. Read PK from PK.txt
    unsigned char PK[2][256][32];

    FILE *fpk = fopen("PK.txt", "r");
    if (!fpk) { printf("Missing PK.txt\n"); return 1; }

    char hexline[65];
    for (int j = 0; j < 256; j++) {
        for (int i = 0; i < 2; i++) {
            if (fscanf(fpk, "%64s", hexline) != 1) {
                printf("Error reading PK.txt\n"); return 1;
            }
            Hex_To_Bytes(PK[i][j], hexline, 32);
        }
    }
    fclose(fpk);

    //2. Read message
    int msgLen;
    unsigned char *msg = Read_File(argv[1], &msgLen);

    //3. Hash the message with SHA-256
    unsigned char msgHash[32];
    SHA256(msg, msgLen, msgHash);
    free(msg);

    //4. Read signature from Signature.txt, then verifies bit by bit
    unsigned char SIG[256][32];

    FILE *fsig = fopen("Signature.txt", "r");
    if (!fsig) { printf("Missing Signature.txt\n"); return 1; }

    for (int k = 0; k < 256; k++) {
        if (fscanf(fsig, "%64s", hexline) != 1) {
            printf("Error reading Signature.txt\n"); return 1;
        }
        Hex_To_Bytes(SIG[k], hexline, 32);
    }
    fclose(fsig);

    int valid = 1;
    for (int k = 0; k < 256; k++) {
        int byte_idx = k / 8;
        int bit_idx  = 7 - (k % 8);  
        int bit = (msgHash[byte_idx] >> bit_idx) & 1;

        //Hash the signature element
        unsigned char hash_of_sig[32];
        SHA256(SIG[k], 32, hash_of_sig);

        //Compare with the corresponding PK element
        if (memcmp(hash_of_sig, PK[bit][k], 32) != 0) {
            valid = 0;
            break;
        }
    }

    //6. Write result
    FILE *fout = fopen("Verification.txt", "wb");
    if (!fout) { printf("Error writing Verification.txt\n"); return 1; }

    if (valid)
        fprintf(fout, "Signature is Valid\n");
    else
        fprintf(fout, "Verification is Invalid\n");

    fclose(fout);
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
int Hex_To_Bytes(unsigned char output[], char input[], int inputLenBytes)
{
    for (int i = 0; i < inputLenBytes; i++) {
        unsigned int byte;
        sscanf(&input[i*2], "%02x", &byte);
        output[i] = (unsigned char)byte;
    }
    return inputLenBytes;
}