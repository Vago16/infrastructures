#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/evp.h>

//function prototypes
void trim_newline(char *s);
unsigned char* Read_File(char fileName[], int *fileLen);
void Write_File(char fileName[], char input[], int input_length);
unsigned char* hex_to_bytes(char *hex, int *out_len);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen);

int main(int argc, char *argv[]) {

    //1.Read the prime modulus q from the file q.txt (written in hexadecimal format)
    BIGNUM *q = NULL;
    FILE *fq = fopen(argv[1], "r");

    char q_hex[4096];
    fgets(q_hex, sizeof(q_hex), fq);
    fclose(fq);

    trim_newline(q_hex);
    BN_hex2bn(&q, q_hex);

    //2.Read the shared seed from the file seed.txt (written in hexadecimal format). The seed is exactly 32 bytes
    int seed_len;
    unsigned char *seed_hex = Read_File(argv[2], &seed_len);

    int seed_bytes_len;
    unsigned char *seed = hex_to_bytes((char*)seed_hex, &seed_bytes_len);

    //3.Read the message from the file message.txt and interpret it as a sequence M = (m1, m2, . . . , mn), where each sub-message mi is a |q|-bit block. 
    int msg_len;
    unsigned char *msg_hex = Read_File(argv[3], &msg_len);

    int msg_bytes_len;
    unsigned char *msg = hex_to_bytes((char*)msg_hex, &msg_bytes_len);

    int block_size = BN_num_bytes(q);
    int n = msg_bytes_len / block_size;

    BIGNUM **m_list = malloc(n * sizeof(BIGNUM*));

    for (int i = 0; i < n; i++) {
        m_list[i] = BN_bin2bn(msg + i*block_size, block_size, NULL);
    }

    //4.Using the shared seed, invoke the ChaCha20 PRNG to generate a pseudo-random byte string of the required length.
    //Store all ai values in a.txt and all bi values in b.txt, one value per line in hex format.
    int prng_len = 2 * n * block_size;
    unsigned char *stream = PRNG(seed, seed_bytes_len, prng_len);

    FILE *fa = fopen("a.txt", "w");
    FILE *fb = fopen("b.txt", "w");

    BIGNUM **a_list = malloc(n * sizeof(BIGNUM*));
    BIGNUM **b_list = malloc(n * sizeof(BIGNUM*));

    for (int i = 0; i < n; i++) {
        a_list[i] = BN_bin2bn(stream + (2*i)*block_size, block_size, NULL);
        b_list[i] = BN_bin2bn(stream + (2*i+1)*block_size, block_size, NULL);

        char *a_hex = BN_bn2hex(a_list[i]);
        char *b_hex = BN_bn2hex(b_list[i]);

        fprintf(fa, "%s\n", a_hex);
        fprintf(fb, "%s\n", b_hex);

        OPENSSL_free(a_hex);
        OPENSSL_free(b_hex);
    }

    fclose(fa);
    fclose(fb);

    //5.Compute the aggregate LC-UMAC tag by partitioning M into n blocks and signing each block mi with its corresponding subkey pair (ai, bi), accumulating the individual MACs modulo q
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *agg = BN_new();
    BN_zero(agg);

    FILE *ft = fopen("tags.txt", "w");

    for (int i = 0; i < n; i++) {
        BIGNUM *tmp = BN_new();
        BIGNUM *sigma = BN_new();

        // tmp = a_i * m_i mod q
        BN_mod_mul(tmp, a_list[i], m_list[i], q, ctx);

        // sigma = tmp + b_i mod q
        BN_mod_add(sigma, tmp, b_list[i], q, ctx);

        // write σ_i
        char *s_hex = BN_bn2hex(sigma);
        fprintf(ft, "%s\n", s_hex);
        OPENSSL_free(s_hex);

        // agg += sigma mod q
        BN_mod_add(agg, agg, sigma, q, ctx);

        BN_free(tmp);
        BN_free(sigma);
    }

    fclose(ft);

    //6.Write the final aggregate LC-UMAC tag σ to the file aggtag.txt in hexadecimal format. 
    // You also need to write individual tags {σi}n i=1 in a separate file tags.txt, each per line in hexadecimal format as well.(done here in previous step)
    char *agg_hex = BN_bn2hex(agg);
    Write_File("aggtag.txt", agg_hex, strlen(agg_hex));
    OPENSSL_free(agg_hex);

    //cleanup
    BN_free(q);
    BN_free(agg);
    BN_CTX_free(ctx);

    free(seed_hex);
    free(seed);
    free(msg_hex);
    free(msg);
    free(stream);

    for (int i = 0; i < n; i++) {
        BN_free(m_list[i]);
        BN_free(a_list[i]);
        BN_free(b_list[i]);
    }

    free(m_list);
    free(a_list);
    free(b_list);

        return 0;
    }

//helper functions
//remove newline
void trim_newline(char *s) {
    int len = strlen(s);
    while (len > 0 && (s[len-1] == '\n' || s[len-1] == '\r')) {
        s[--len] = '\0';
    }
}

//read file (hex string)
unsigned char* Read_File(char fileName[], int *fileLen) {
    FILE *pFile = fopen(fileName, "r");
    if (!pFile) {
        printf("Error opening file.\n");
        exit(0);
    }

    fseek(pFile, 0L, SEEK_END);
    int size = ftell(pFile) + 1;
    fseek(pFile, 0L, SEEK_SET);

    unsigned char *output = malloc(size);
    fgets((char*)output, size, pFile);
    fclose(pFile);

    trim_newline((char*)output);
    *fileLen = strlen((char*)output);
    return output;
}

//write string to file
void Write_File(char fileName[], char input[], int input_length) {
    FILE *pFile = fopen(fileName, "w");
    if (!pFile) {
        printf("Error opening file.\n");
        exit(0);
    }
    fwrite(input, 1, input_length, pFile);
    fclose(pFile);
}

//convert hex string to bytes
unsigned char* hex_to_bytes(char *hex, int *out_len) {
    int len = strlen(hex);
    int bytes_len = len / 2;
    unsigned char *bytes = malloc(bytes_len);

    for (int i = 0; i < bytes_len; i++) {
        sscanf(hex + 2*i, "%2hhx", &bytes[i]);
    }

    *out_len = bytes_len;
    return bytes;
}

//convert bytes to hex string
void Convert_to_Hex(char output[], unsigned char input[], int inputlength) {
    for (int i = 0; i < inputlength; i++) {
        sprintf(&output[2*i], "%02x", input[i]);
    }
    output[2*inputlength] = '\0';
}

//ChaCha20 PRNG
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char *out = malloc(prnglen);

    unsigned char nonce[16] = {0};
    unsigned char *zeros = calloc(prnglen, 1);

    int len;
    EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, seed, nonce);
    EVP_EncryptUpdate(ctx, out, &len, zeros, prnglen);

    EVP_CIPHER_CTX_free(ctx);
    free(zeros);

    return out;
}