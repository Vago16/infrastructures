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

    //1.Bob reads the ciphertext from the ”Ciphertext.txt” file.

    //2.Bob reads the shared seed from the ”SharedSeed.txt” file as unsigned char. The seed is 32 Bytes.
    
    //3.Bob generates the secret key from the shared seed based on utilizing the PRNG function from OpenSSL. The key size must match the message length.

    //4.Bob XORs the received ciphertext with the secret key to obtain the plaintext: (plaintext = ciphertext ^ key).

    //5.Bob writes the decrypted plaintext in a file named “Plaintext.txt”.

    //6.Bob hashes the plaintext via SHA256 and writes the Hex format of the hash in a file named ”Hash.txt” for Alice to verify.

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
