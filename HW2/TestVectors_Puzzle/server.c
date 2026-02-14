#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

//SERVER

// Function Prototypes
char* Read_File(const char *filename, int *length);
int Write_File(const char *filename, const char *data);
int Read_Int_From_File(const char *filename);
int Write_Int_To_File(const char *filename, int value);
int Hex_to_Bytes(const char *hex, unsigned char *bytes, int hex_len);
int Bytes_to_Hex(const unsigned char *bytes, int byte_len, char *hex);
int Compute_SHA256(const unsigned char *data, int data_len, unsigned char *output);
void Print_Hex(const char *label, const unsigned char *data, int len);

int main(int argc, char *argv[]) {

    //check if right amount of arguments are passed inline, 3 are needed, ie example like "./Server Challenge1.txt Difficulty1.txt"
    if (argc != 3) {
        printf("3 arguments needed: server file, Challenge$i.txt, and Difficulty$i.txt\n");
        return 1;
    }

    //1. Server reads the challenge data from a file named “Challenge$i.txt” (32 bytes hex) as char.
    //  • Technically, this contains timestamp || server nonce
    int challenge_len;
    char *challenge_hex = Read_File(argv[1], &challenge_len);
    //if Challenge$i.txt not passed, exit
    if (!challenge_hex) {
        printf("Challenge.txt has not been passed\n");
        return 1;
    }

    //if challenge_len not 32 bytes(64 in hex), pass warning
    if (challenge_len != 64) {
        printf("Length of challenge is not 32 bytes\n");
        //free(challenge_hex);
        //return 1;
    }

    //2. Server reads the difficulty level from a file named “Difficulty$i.txt” (integer) as ASCII integer.
    //  • Value between 8 and 20 representing k-bit difficulty
    int difficulty_k = Read_Int_From_File(argv[2]);
    //if Difficulty$i.txt not passed, exit
    if (difficulty_k < 8 || difficulty_k > 20) {
        printf("Difficulty.txt does not contain a value between 8 and 20\n");
        free(challenge_hex);
        return 1;
    }

    //3. Server writes the challenge to “puzzle challenge.txt” as hex string.
    Write_File("challenge_hex.txt", challenge_hex);    

    //4. Server writes the difficulty k to “puzzle k.txt” as ASCII integer.
    Write_Int_To_File("puzzle_key.txt", difficulty_k); 

    //cleanup of pointers
    free(challenge_hex);

    return 0;
}


/*
    File I/O Functions
*/

 // Read File
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
    
    // Remove trailing whitespace
    while (read_size > 0 && (buffer[read_size-1] == '\n' || 
                              buffer[read_size-1] == '\r' || 
                              buffer[read_size-1] == ' ')) {
        buffer[--read_size] = '\0';
    }
    
    *length = read_size;
    fclose(file);
    return buffer;
}

 // Write string to file
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

/*
    Hex Conversion Functions
*/

 // Convert hex string to byte array
int Hex_to_Bytes(const char *hex, unsigned char *bytes, int hex_len) {
    if (hex_len % 2 != 0) {
        fprintf(stderr, "Error: Hex string length must be even\n");
        return -1;
    }
    
    int byte_len = hex_len / 2;
    for (int i = 0; i < byte_len; i++) {
        unsigned int byte;
        if (sscanf(hex + (i * 2), "%2x", &byte) != 1) {
            fprintf(stderr, "Error: Invalid hex character at position %d\n", i * 2);
            return -1;
        }
        bytes[i] = (unsigned char)byte;
    }
    
    return byte_len;
}

 // Convert byte array to hex string
int Bytes_to_Hex(const unsigned char *bytes, int byte_len, char *hex) {
    for (int i = 0; i < byte_len; i++) {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }
    hex[byte_len * 2] = '\0';
    return byte_len * 2;
}

/*
    Cryptographic Functions
*/

// SHA256 hash, edited to compile correctly
int Compute_SHA256(const unsigned char *data, int data_len, unsigned char *output) {

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    if (EVP_DigestUpdate(ctx, data, data_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    if (EVP_DigestFinal_ex(ctx, output, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    return 0;
}

/*
    Utility Functions
*/

int Read_Int_From_File(const char *filename) {
    int length;
    char *str = Read_File(filename, &length);
    if (!str) return -1;
    
    int value = atoi(str);
    free(str);
    return value;
}

int Write_Int_To_File(const char *filename, int value) {
    char buffer[32];
    sprintf(buffer, "%d", value);
    return Write_File(filename, buffer);
}

void Print_Hex(const char *label, const unsigned char *data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}
