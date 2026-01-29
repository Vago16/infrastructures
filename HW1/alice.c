// Header files
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

// Function prototypes 
unsigned char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], char input[], int input_length);
void Convert_to_Hex (char output[], unsigned char input[], int inputlength);
void Show_in_Hex (char name[], unsigned char hex[], int hexlen);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);

// check if a file exists
static int file_exists(const char *filename) {
    FILE *f = fopen(filename, "rb");
    if (f) { fclose(f); return 1; }
    return 0;
}

// read text file and trim  
static unsigned char* Read_Text_Trim(char fileName[], int *outLen) {
    int n = 0;
    unsigned char *raw = Read_File(fileName, &n);
    while (n > 0 && isspace((unsigned char)raw[n - 1])) n--;
    raw[n] = '\0';
    *outLen = n;
    return raw;
}

int main(int argc, char *argv[]) {

    if (argc != 3) {
        printf("Usage: %s <MessageFile> <SharedSeedFile>\n", argv[0]);
        return 1;
    }

    // 1. Alice reads message
    unsigned char *message;
    int message_len = 0;
    message = Read_File(argv[1], &message_len);

    if (message_len < 32) {
        printf("The message size must be equal or greater than 32 bytes.\n");
        free(message);
        return 1;
    }

    // 2. Alice reads shared seed 
    unsigned char *seed;
    int seed_len = 0;
    seed = Read_File(argv[2], &seed_len);

    if (seed_len != 32) {
        printf("SharedSeed must be exactly 32 bytes.\n");
        free(message);
        free(seed);
        return 1;
    }

    // 3. Generate key stream using PRNG 
    unsigned char *key = PRNG(seed, (unsigned long)seed_len, (unsigned long)message_len);

    // 4. Write Key.txt as hex
    char *key_hex = (char*)malloc(2 * message_len + 1);
    if (!key_hex) { printf("malloc failed\n"); exit(1); }
    Convert_to_Hex(key_hex, key, message_len);
    Write_File("Key.txt", key_hex, 2 * message_len);

    // 5. XOR message ^ key -> ciphertext bytes
    unsigned char *cipher = (unsigned char*)malloc(message_len);
    if (!cipher) { printf("malloc failed\n"); exit(1); }
    for (int i = 0; i < message_len; i++) cipher[i] = message[i] ^ key[i];

    // 6. Write Ciphertex as hex
    char *cipher_hex = (char*)malloc(2 * message_len + 1);
    if (!cipher_hex) { printf("malloc failed\n"); exit(1); }
    Convert_to_Hex(cipher_hex, cipher, message_len);
    Write_File("Ciphertext.txt", cipher_hex, 2 * message_len);

    // 7-8. If Hash.txt exists , verify and write Acknowledgment.txt
    if (file_exists("Hash.txt")) {
        unsigned char *local_hash = Hash_SHA256(message, (unsigned long)message_len);

        char local_hash_hex[2 * SHA256_DIGEST_LENGTH + 1];
        Convert_to_Hex(local_hash_hex, local_hash, SHA256_DIGEST_LENGTH);

        int bob_hash_len = 0;
        unsigned char *bob_hash_hex = Read_Text_Trim("Hash.txt", &bob_hash_len);

        if (bob_hash_len == 2 * SHA256_DIGEST_LENGTH &&
            strcmp((char*)local_hash_hex, (char*)bob_hash_hex) == 0) {
            Write_File("Acknowledgment.txt", "Acknowledgment Successful",
                       (int)strlen("Acknowledgment Successful"));
        } else {
            Write_File("Acknowledgment.txt", "Acknowledgment Failed",
                       (int)strlen("Acknowledgment Failed"));
        }

        free(local_hash);
        free(bob_hash_hex);
    }

    // Cleanup
    free(message);
    free(seed);
    free(key);
    free(key_hex);
    free(cipher);
    free(cipher_hex);

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
    FILE *pFile = fopen(fileName, "wb");   
    if (pFile == NULL) {
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
    for (int i = 0; i < inputlength; i++) {
        sprintf(&output[2*i], "%02x", input[i]);
    }
    output[2*inputlength] = '\0';  
}

/*============================
        PRNG Fucntion 
==============================*/
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen)
{
    (void)seedlen; // key must be 32 bytes for ChaCha20

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
