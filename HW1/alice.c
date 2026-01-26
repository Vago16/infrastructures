//Header files
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

//Function prototypes
unsigned char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], char input[], int input_length);
void Convert_to_Hex (char output[], unsigned char input[], int inputlength);
void Show_in_Hex (char name[], unsigned char hex[], int hexlen);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);


int main(int argc, char *argv[]) {

    //1.Alice reads the message from the ”Message.txt” file as unsigned char. The message size must be equal or greater than 32 bytes.
    unsigned char *message; //according to specifications
    int message_len;    //file length
    
    message = Read_File(argv[1], &message_len);

    //check if message length is less than 32 bytes
    if (message_len < 32) {
        printf("The message size must be equal or greater than 32 bytes.\n");
        exit(0);
    }

    //2.Alice reads the shared seed from the ”SharedSeed.txt” file as unsigned char. The seed is 32 Bytes.
    unsigned char *shared_seed; //according to specifications
    int shared_seed_len;    //file length

    message = Read_File(argv[2], &shared_seed_len); //size already should 32 bytes

    //3.Alice generates the secret key from the shared seed based on utilizing the PRNG function from OpenSSL. The key size must match the message length.
    unsigned char *key;

    key = PRNG(shared_seed, shared_seed_len, message_len);

    //4.Alice writes the Hex format of the key in a file named “Key.txt”.
    char *key_in_hex = malloc(2 * message_len);
    Convert_to_Hex(key_in_hex, key, message_len);   //convert key to hex
    Write_File("Key.txt", key_in_hex, 2 * message_len);   //write key(now in hex) to file

    //5.Alice XORs the message with the secret key to obtain the ciphertext: (Ciphertext = Message ^ Key).
    unisgned char *ctext = malloc(message_len);

    //loop to XOR every byte
    for (i = 0; i< message_len; i++) {
        ctext[i] = message[i] ^ key[i];
    }

    //6.Alice writes the Hex format of the ciphertext in a file named “Ciphertext.txt”.
    char *ctext_in_hex = malloc(2 * message_len);
    Convert_to_Hex(ctext_in_hex, ctext, message_len);   //convert key to hex
    Write_File("Ciphertext.txt", ctext_in_hex, 2 * message_len);   //write key(now in hex) to file

    //7.Once Bob has processed the message, Alice reads Bob’s computed hash from ”Hash.txt”.

    //8.f the comparison is successful, Alice can be confident that Bob has received the accurate message. 
    // She then writes ”Acknowledgment Successful” in a file called ”Acknowledgment.txt.” Conversely, if the comparison
    // fails, she records ”Acknowledgment Failed.
    
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
    FILE *pFile;
	pFile = fopen(fileName, "r");
	if (pFile == NULL)
	{
		printf("Error opening file.\n");
		exit(0);
	}
    fseek(pFile, 0L, SEEK_END);
    int temp_size = ftell(pFile)+1;
    fseek(pFile, 0L, SEEK_SET);
    unsigned char *output = (unsigned char*) malloc(temp_size);
	fgets(output, temp_size, pFile);
	fclose(pFile);

    *fileLen = temp_size-1;
	return output;
}

/*============================
        Write to File
==============================*/
void Write_File(char fileName[], char input[], int input_length){
  FILE *pFile;
  pFile = fopen(fileName,"w");
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
    printf("Hex format: %s\n", output);  //remove later
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

    unsigned char zeros[prnglen];
    memset(zeros, 0, prnglen);

    int outlen;
    EVP_EncryptUpdate(ctx, pseudoRandomNumber, &outlen, zeros, prnglen);
    EVP_EncryptFinal(ctx, pseudoRandomNumber, &outlen);

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
