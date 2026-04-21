//Lamport Sign
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

//function prototypes
unsigned char* Read_File(char fileName[], int *fileLen);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);
int Hex_To_Bytes(unsigned char output[], char input[], int inputLenBytes);

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s Message.txt\n", argv[0]);
        return 1;
    }

    //1. Read SK from SK.txt 
    unsigned char SK[2][256][32];

    FILE *fsk = fopen("SK.txt", "r");
    if (!fsk) { printf("Missing SK.txt\n"); return 1; }

    char hexline[65];
    for (int j = 0; j < 256; j++) {
        for (int i = 0; i < 2; i++) {
            if (fscanf(fsk, "%64s", hexline) != 1) {
                printf("Error reading SK.txt\n"); return 1;
            }
            Hex_To_Bytes(SK[i][j], hexline, 32);
        }
    }
    fclose(fsk);

    //2. Read message
    int msgLen;
    unsigned char *msg = Read_File(argv[1], &msgLen);

    //3. Hash the message  SHA using-256
    unsigned char msgHash[32];
    SHA256(msg, msgLen, msgHash);
    free(msg);

    //4. Sign bit by bit sccording to Lamport OTS Variant I
    FILE *fsig = fopen("Signature.txt", "wb");
    if (!fsig) { printf("Error writing Signature.txt\n"); return 1; }

    char hex[65];
    for (int k = 0; k < 256; k++) {
        int byte_idx = k / 8;
        int bit_idx  = 7 - (k % 8);
        int bit = (msgHash[byte_idx] >> bit_idx) & 1;

        Convert_to_Hex(hex, SK[bit][k], 32);
        if (k == 255)
            fprintf(fsig, "%s", hex);         //no newline on last line
        else
            fprintf(fsig, "%s\n", hex);
    }
    fclose(fsig);

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
int Hex_To_Bytes(unsigned char output[], char input[], int inputLenBytes)
{
    for (int i = 0; i < inputLenBytes; i++) {
        unsigned int byte;
        sscanf(&input[i*2], "%02x", &byte);
        output[i] = (unsigned char)byte;
    }
    return inputLenBytes;
}