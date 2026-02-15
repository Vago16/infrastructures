#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

//VERIFY

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
    if (argc != 4) {
        printf("4 arguments needed: verify file, puzzle_challenge.txt, puzzle_k.txt, solution_nonce.txt\n");
        return 1;
    }

    //1. Server reads the puzzle challenge from file “puzzle challenge.txt” as char, so that you can easily convert it from hex to bytes.
    int challenge_len;
    char *challenge_hex = Read_File(argv[1], &challenge_len);
    //if puzzle_challenge.txt not passed, exit
    if (!challenge_hex) {
        printf("puzzle_challenge.txt has not been passed\n");
        return 1;
    }

    unsigned char challenge_bytes[32];  //length of bytes should be 32
    if (Hex_to_Bytes(challenge_hex, challenge_bytes, challenge_len) != 32) {
        printf("Challenge is not 32 bytes\n");
        free(challenge_hex);
        return 1;
    }

    //2. Server reads the difficulty k from file “puzzle k.txt” as ASCII integer.
    int difficulty_k = Read_Int_From_File(argv[2]);
    //if puzzle_key.txt not passed, exit
    if (difficulty_k < 8 || difficulty_k > 20) {
        printf("Difficulty.txt does not contain a value between 8 and 20\n");
        free(challenge_hex);
        return 1;
    }

    //3. Server reads the solution nonce from file “solution nonce.txt”, as char, so that you can easily convert it from hex to bytes.
    int nonce_len;
    char *nonce_hex = Read_File(argv[3], &nonce_len);
    if (!nonce_hex) {
        printf("Nonce was not passed.\n");
        free(challenge_hex);
        return 1;
    }

    unsigned char nonce_bytes[8];
    if (Hex_to_Bytes(nonce_hex, nonce_bytes, nonce_len) != 8) {
        printf("Nonce is not 8 bytes.\n");
        free(challenge_hex);
        free(nonce_hex);
        return 1;
    }

    //4. Server recomputes the hash: Construct data = challenge || nonce, Compute hash = SHA256(data)
    unsigned char chall_and_nonce[40];
    unsigned char hash_buf[32];

    memcpy(chall_and_nonce, challenge_bytes, 32);
    memcpy(chall_and_nonce + 32, nonce_bytes, 8);

    //Construct with SHA the data = challenge || nonce
        if (Compute_SHA256(chall_and_nonce, 40, hash_buf) != 0) {
            printf("SHA256 hash failed\n");
            free(challenge_hex);
            free(nonce_hex);
            return 1;
        }

    //5. Server verifies leading zeros: check if hash has k leading zero bits, uses smae checking logic as client
    int full_zero_bytes = difficulty_k / 8;
    int partial_bits = difficulty_k % 8;
    unsigned char bit_mask = 0;

    //use bit masking if there are partial bits
    if (partial_bits != 0) {
        bit_mask = 0xFF << (8 - partial_bits);
    }

    //check if first k bits are zero        
    int valid = 1;
    for (int i = 0; i < full_zero_bytes; i++) {
        if (hash_buf[i] != 0x00) {
            valid = 0;
            break;
        }
    }

    //Partial bit check
    if (valid && partial_bits != 0) {
        if ((hash_buf[full_zero_bytes] & bit_mask) != 0x00) {
            valid = 0;      //should be full zeros
        }
    }

    //6. Server outputs result:
    // • If valid: Write “ACCEPT” to “verification_result.txt”, exit 0
    // • If invalid: Write “REJECT” to “verification_result.txt”, exit 1
    if (valid) {
        Write_File("verification_result.txt", "ACCEPT");
        //cleanup
        free(challenge_hex);
        free(nonce_hex);
        return 0;
    } else {
        Write_File("verification_result.txt", "REJECT");
        //cleanup
        free(challenge_hex);
        free(nonce_hex);
        return 1;
    }
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
