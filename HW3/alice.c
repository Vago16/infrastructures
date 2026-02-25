//Header files
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>


//alice

//Function prototypes
unsigned char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], char input[], int input_length);
void Convert_to_Hex (char output[], unsigned char input[], int inputlength);
void Show_in_Hex (char name[], unsigned char hex[], int hexlen);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);
unsigned char* AES_CTR_Encrypt(unsigned char *key, unsigned char *plaintext, int plaintext_len, int *ciphertext_len);
unsigned char* HMAC_SHA256(unsigned char *key, int key_len, unsigned char *data, int data_len, unsigned int *hmac_len);


int main(int argc, char *argv[]) {

    //First, Alice reads the shared seed from a file named “SharedSeed.txt” and uses the PRNG (ChaCha20) to create the initial symmetric key k1.

    // • For every message Mi, i = 1, . . . , n, performs the following operations:
    // 1. Compute the ciphertext: Ci = Enc(ki, Mi).

    // 2. Individual HMAC: Si = HM AC(ki, Ci). 

    // 3. Aggregate HMAC: S1,i = H(S1,i−1||Si)

    // 4. Update the key for every message ki+1 = H(ki).

    // • After processing all messages, Alice writes the following files:
    // – Keys in ”Keys.txt”
    // • Alice converts the keys into Hex and writes them in a file named “Keys.txt” in multiple lines.

    // – Ciphertexts in ”Ciphertexts.txt”
    // • Alice converts the ciphertexts into Hex and writes them in a file named “Ciphertexts.txt” in multiple lines.

    // – Individual HMACs in ”IndividualHMACs.txt”
    // • Alice converts the individual HMACs into Hex and writes them in a file named “IndividualHMACs.txt” in multiple lines.

    // – Aggregated HMAC in ”AggregatedHMAC.txt”
    // • Alice converts the aggregated HMAC into Hex and writes it in a file named “AggregatedHMAC.txt”.
    
    return 0;
}


/*************************************************************
					F u n c t i o n s
**************************************************************/

/*============================
        Read from File
==============================*/
unsigned char* Read_File(const char *filename, int *length) {

    FILE *file = fopen(filename, "rb");  
    if (!file) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        exit(1);
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *buffer = malloc(file_size);
    if (!buffer) {
        fclose(file);
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }

    size_t read_size = fread(buffer, 1, file_size, file);
    fclose(file);

    *length = read_size;
    return buffer;
}

/*============================
        Write to File
==============================*/
void Write_File(char fileName[], char input[], int input_length){
  FILE *pFile;
  pFile = fopen(fileName,"wb");
  if (pFile == NULL){
    printf("Error opening file. \n");
    exit(0);
  }
  //fputs(input, pFile);
  fwrite(input, 1, input_length, pFile);
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
}

/*============================
        PRNG Fucntion 
==============================*/
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char *pseudoRandomNumber = malloc(prnglen);

    unsigned char nonce[16] = {0};

    EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, seed, nonce);

    unsigned char *zeros = calloc(prnglen, 1);
    int outlen;
    int total = 0;

    EVP_EncryptUpdate(ctx, pseudoRandomNumber, &outlen, zeros, prnglen);
    total += outlen;

    EVP_EncryptFinal_ex(ctx, pseudoRandomNumber + total, &outlen);
    total += outlen;

    free(zeros);
    EVP_CIPHER_CTX_free(ctx);
    return pseudoRandomNumber;
}

/*============================
        SHA-256 Fucntion
==============================*/
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


//AES-CTR Encrypt
unsigned char* AES_CTR_Encrypt(unsigned char *key, unsigned char *plaintext, int plaintext_len, int *ciphertext_len) 
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    unsigned char IV[16] = "abcdefghijklmnop";  //initialization vector 

    unsigned char *ciphertext = malloc(plaintext_len);

    int len;
    int total_len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, IV);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    total_len += len;

    EVP_EncryptFinal_ex(ctx, ciphertext + total_len, &len);
    total_len += len;

    EVP_CIPHER_CTX_free(ctx);

    *ciphertext_len = total_len;
    return ciphertext;
}

//AES-CTR Decrypt

//HMAC-SHA
unsigned char* HMAC_SHA256(unsigned char *key, int key_len, unsigned char *data, int data_len, unsigned int *hmac_len) 
{
    unsigned char *result = malloc(SHA256_DIGEST_LENGTH);

    HMAC(
        EVP_sha256(), key, key_len, data, data_len, result, hmac_len
    );

    return result;
}

