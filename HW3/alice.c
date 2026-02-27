//Header files
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>


//alice

//Function prototypes
unsigned char* Read_File (const char fileName[], int *fileLen);
void Write_File(char fileName[], char input[], int input_length, char mode[]);
void Convert_to_Hex (char output[], unsigned char input[], int inputlength);
void Show_in_Hex (char name[], unsigned char hex[], int hexlen);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);
unsigned char* AES_CTR_Encrypt(unsigned char *key, unsigned char *plaintext, int plaintext_len, int *ciphertext_len);
unsigned char* HMAC_SHA256(unsigned char *key, int key_len, unsigned char *data, int data_len, unsigned int *hmac_len);
void Write_Hex_Line(char filename[], unsigned char data[], int len, char mode[]);


int main(int argc, char *argv[]) {

    //First, Alice reads the shared seed from a file named “SharedSeed.txt” and uses the PRNG (ChaCha20) to create the initial symmetric key k1.
    int seed_len;
    unsigned char *seed = Read_File(argv[2], &seed_len);

    //create the initial symmetric key k1
    unsigned char *ki = PRNG(seed, seed_len, 32);
   
    // Second, read from "Messages.txt"
    int messages_len;
    unsigned char *messages_buf_raw = Read_File(argv[1], &messages_len);
    unsigned char *messages_buf = malloc(10240);
    int j = 0;

    for (int i = 0; i < messages_len; i++) {
        if (messages_buf_raw[i] != '\n' && messages_buf_raw[i] != '\r') {
            messages_buf[j++] = messages_buf_raw[i];
        }
    }

    free(messages_buf_raw);

    if (j != 10240) {
        printf("Error: cleaned message size is %d, expected 10240\n", j);
        exit(1);
    }

    messages_len = 10240;

    int num_messages = 10;
    int msg_size = 1024;

    //Third, create array of pointers to each message, points to start of each message
    unsigned char *messages[10];
    for (int i = 0; i < num_messages; i++) {
        messages[i] = messages_buf + i * msg_size;
    }

    //Fourth, create storage for outputs from main message loop
    unsigned char *ciphertexts[10];
    unsigned char *individual_hmacs[10];
    unsigned char *keys[10];       // store ki for each message
    int ciphertext_lens[10];
    unsigned char *agg_hmac = NULL; 
    unsigned int hmac_len;

    //Fifth, initialize aggregated HMAC
    agg_hmac = malloc(SHA256_DIGEST_LENGTH);
    memset(agg_hmac, 0, SHA256_DIGEST_LENGTH);

    //MAIN LOOP over messages
    for (int i = 0; i < num_messages; i++) {
    // • For every message Mi, i = 1, . . . , n, performs the following operations:

    // 1. Compute the ciphertext: Ci = Enc(ki, Mi).
    int this_msg_len = 1024;  // default length

    int ctext_len;
    ciphertexts[i] = AES_CTR_Encrypt(ki, messages[i], this_msg_len, &ctext_len);
    ciphertext_lens[i] = ctext_len;

    // 2. Individual HMAC: Si = HM AC(ki, Ci). 
    individual_hmacs[i] = HMAC_SHA256(ki, 32, ciphertexts[i], ctext_len, &hmac_len);

    // 3. Aggregate HMAC: S1,i = H(S1,i−1||Si)
    if (i == 0) {
        //just hash the first input for the first element
        agg_hmac = Hash_SHA256(individual_hmacs[0], SHA256_DIGEST_LENGTH);
    }
    else {
        unsigned char temp[64];

        memcpy(temp, agg_hmac, 32);
        memcpy(temp + 32, individual_hmacs[i], 32);

        unsigned char *new_agg = Hash_SHA256(temp, 64);

        free(agg_hmac);
        agg_hmac = new_agg;
    }
    //unsigned char *temp = malloc(64);
    //memcpy(temp, agg_hmac, 32);
    //memcpy(temp + 32, individual_hmacs[i], 32);

    //unsigned char *temp = malloc(SHA256_DIGEST_LENGTH + SHA256_DIGEST_LENGTH);
    //memcpy(temp, agg_hmac, SHA256_DIGEST_LENGTH);
    //memcpy(temp + SHA256_DIGEST_LENGTH, individual_hmacs[i], SHA256_DIGEST_LENGTH);

    //agg_hmac = Hash_SHA256(temp, SHA256_DIGEST_LENGTH + SHA256_DIGEST_LENGTH);

    //unsigned char *new_agg = Hash_SHA256(temp, 64);
    //free(agg_hmac);
    //agg_hmac = new_agg;

    //free(temp);


    // 4. Update the key for every message ki+1 = H(ki).
    keys[i] = malloc(32);
    memcpy(keys[i], ki, 32);

    unsigned char *next_ki = Hash_SHA256(ki, 32);
    free(ki);       //freeing up old key
    ki = next_ki;

    }
    // • After processing all messages, Alice writes the following files:
    // – Keys in ”Keys.txt”
    // • Alice converts the keys into Hex and writes them in a file named “Keys.txt” in multiple lines.
    Write_File("Keys.txt", "", 0, "wb");  //create file

    for (int i = 0; i < num_messages; i++) {
        Write_Hex_Line("Keys.txt", keys[i], 32, "ab");  //append 10 lines of keys
    }

    // Ensure file ends with newline
    Write_File("Keys.txt", "\n", 1, "ab");

    for (int i = 0; i < num_messages; i++) {
        if (i < num_messages - 1) {
            Write_Hex_Line("Keys.txt", keys[i], 32, i==0 ? "wb" : "ab"); // with newline
        } else {
            // Last line: write hex only, no newline
            char hex[64];
            Convert_to_Hex(hex, keys[i], 32);
            Write_File("Keys.txt", hex, 64, i==0 ? "wb" : "ab");
        }
    }

    // – Ciphertexts in ”Ciphertexts.txt”
    // • Alice converts the ciphertexts into Hex and writes them in a file named “Ciphertexts.txt” in multiple lines.
    Write_File("Ciphertexts.txt", "", 0, "wb");  //create file

    for (int i = 0; i < num_messages; i++) {
        if (i < num_messages - 1) {
            Write_Hex_Line("Ciphertexts.txt", ciphertexts[i], ciphertext_lens[i], i == 0 ? "wb" : "ab");
        } else {
            char hex[ciphertext_lens[i] * 2];
            Convert_to_Hex(hex, ciphertexts[i], ciphertext_lens[i]);
            Write_File("Ciphertexts.txt", hex, ciphertext_lens[i] * 2, i == 0 ? "wb" : "ab");
        }
    }

    // – Individual HMACs in ”IndividualHMACs.txt”
    // • Alice converts the individual HMACs into Hex and writes them in a file named “IndividualHMACs.txt” in multiple lines.
    Write_File("IndividualHMACs.txt", "", 0, "wb");  //create file

    for (int i = 0; i < num_messages; i++) {
    if (i < num_messages - 1) {
        Write_Hex_Line("IndividualHMACs.txt", individual_hmacs[i], 32, i == 0 ? "wb" : "ab");
    } else {
        char hex[64];
        Convert_to_Hex(hex, individual_hmacs[i], 32);
        Write_File("IndividualHMACs.txt", hex, 64, i == 0 ? "wb" : "ab");
    }
}

    // – Aggregated HMAC in ”AggregatedHMAC.txt”
    // • Alice converts the aggregated HMAC into Hex and writes it in a file named “AggregatedHMAC.txt”.
    char hex[64];
    Convert_to_Hex(hex, agg_hmac, 32);
    Write_File("AggregatedHMAC.txt", hex, 64, "wb");

    //cleanup
    free(seed);
    free(ki);
    free(messages_buf);
    free(agg_hmac);
    //cleanup of array elements
    for (int i = 0; i < num_messages; i++) {
        free(ciphertexts[i]);
        free(individual_hmacs[i]);
        free(keys[i]);
    }

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
void Write_File(char fileName[], char input[], int input_length, char mode[]) {
    FILE *pFile = fopen(fileName, mode);   // "wb"-write/create file or "ab"-append to file

    if (pFile == NULL){
        printf("Error opening file.\n");
        exit(1);
    }

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

//Write_Hex_line function- appending hex line by line
void Write_Hex_Line(char filename[], unsigned char data[], int len, char mode[])
{
    char *hex = malloc(len * 2);

    Convert_to_Hex(hex, data, len);

    Write_File(filename, hex, len * 2, mode);
    Write_File(filename, "\n", 1, "ab");
    

    free(hex);
}
