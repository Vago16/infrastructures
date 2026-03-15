#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/rand.h>

#include "RequiredFunctions.c"

int main(int argc, char *argv[])
{
	if (argc != 5)
	{
		fprintf(stderr,
				"Usage: %s <Client_Signature> <Client_temp_PK> <AS_temp_SK> <AS_temp_PK>\n",
				argv[0]);
		return EXIT_FAILURE;
	}

	const char *client_sig_path = argv[1];
	const char *client_temp_pk_path = argv[2];
	const char *as_temp_sk_path = argv[3];
	const char *as_temp_pk_path = argv[4];

	unsigned char key_client_as[32];
	unsigned char key_client_tgs[32];

	/* STEP 0: verify required input files exist */
	if (!file_exists(client_sig_path))
	{
		fprintf(stderr, "Missing file: %s\n", client_sig_path);
		return EXIT_FAILURE;
	}
	if (!file_exists(client_temp_pk_path))
	{
		fprintf(stderr, "Missing file: %s\n", client_temp_pk_path);
		return EXIT_FAILURE;
	}
	if (!file_exists(as_temp_sk_path))
	{
		fprintf(stderr, "Missing file: %s\n", as_temp_sk_path);
		return EXIT_FAILURE;
	}
	if (!file_exists(as_temp_pk_path))
	{
		fprintf(stderr, "Missing file: %s\n", as_temp_pk_path);
		return EXIT_FAILURE;
	}
	if (!file_exists("Client_PK.txt"))
	{
		fprintf(stderr, "Missing file: Client_PK.txt\n");
		return EXIT_FAILURE;
	}
	if (!file_exists("Key_Client_TGS.txt"))
	{
		fprintf(stderr, "Missing file: Key_Client_TGS.txt\n");
		return EXIT_FAILURE;
	}
	if (!file_exists("Key_AS_TGS.txt"))
	{
		fprintf(stderr, "Missing file: Key_AS_TGS.txt\n");
		return EXIT_FAILURE;
	}

	/* STEP 1: verify client signature */
	if (!ecdsa_verify_file_from_hex("Client_PK.txt", client_temp_pk_path, client_sig_path))
	{
		fprintf(stderr, "Client signature verification failed\n");
		return EXIT_FAILURE;
	}

	/* STEP 2: derive shared secret and write shared_secret.txt */
	unsigned char *shared_secret = NULL;
	size_t shared_secret_len = 0;
	if (!ecdh_shared_secret_files(as_temp_sk_path, client_temp_pk_path,
	                              &shared_secret, &shared_secret_len))
	{
		fprintf(stderr, "Failed to derive shared secret\n");
		return EXIT_FAILURE;
	}

	if (!write_hex_file("shared_secret.txt", shared_secret, shared_secret_len))
	{
		free(shared_secret);
		fprintf(stderr, "Failed to write shared_secret.txt\n");
		return EXIT_FAILURE;
	}

	/* STEP 3: derive Key_Client_AS and write Key_Client_AS.txt */
	if (!sha256_bytes(shared_secret, shared_secret_len, key_client_as))
	{
		free(shared_secret);
		fprintf(stderr, "Failed to derive Key_Client_AS\n");
		return EXIT_FAILURE;
	}
	free(shared_secret);

	if (!write_hex_file("Key_Client_AS.txt", key_client_as, 32))
	{
		fprintf(stderr, "Failed to write Key_Client_AS.txt\n");
		return EXIT_FAILURE;
	}

	/* STEP 4: read Key_Client_TGS.txt */
	unsigned char *key_client_tgs_raw = NULL;
	size_t key_client_tgs_len = 0;
	if (!read_hex_file_bytes("Key_Client_TGS.txt", &key_client_tgs_raw, &key_client_tgs_len))
	{
		fprintf(stderr, "Failed to read Key_Client_TGS.txt\n");
		return EXIT_FAILURE;
	}
	if (key_client_tgs_len != 32)
	{
		free(key_client_tgs_raw);
		fprintf(stderr, "Key_Client_TGS length is not 32 bytes\n");
		return EXIT_FAILURE;
	}
	memcpy(key_client_tgs, key_client_tgs_raw, 32);

	char *key_client_tgs_hex = bytes_to_hex(key_client_tgs_raw, key_client_tgs_len);
	free(key_client_tgs_raw);
	if (!key_client_tgs_hex)
	{
		fprintf(stderr, "Failed to encode Key_Client_TGS as hex\n");
		return EXIT_FAILURE;
	}

	/* STEP 5: build and encrypt TGT */
	unsigned char *key_as_tgs = NULL;
	size_t key_as_tgs_len = 0;
	if (!read_hex_file_bytes("Key_AS_TGS.txt", &key_as_tgs, &key_as_tgs_len))
	{
		free(key_client_tgs_hex);
		fprintf(stderr, "Failed to read Key_AS_TGS.txt\n");
		return EXIT_FAILURE;
	}
	if (key_as_tgs_len != 32)
	{
		free(key_client_tgs_hex);
		free(key_as_tgs);
		fprintf(stderr, "Key_AS_TGS length is not 32 bytes\n");
		return EXIT_FAILURE;
	}

	size_t tgt_plain_len = strlen("Client") + strlen(key_client_tgs_hex);
	char *tgt_plain = malloc(tgt_plain_len + 1);
	if (!tgt_plain)
	{
		free(key_client_tgs_hex);
		free(key_as_tgs);
		fprintf(stderr, "Memory allocation failed\n");
		return EXIT_FAILURE;
	}
	strcpy(tgt_plain, "Client");
	strcat(tgt_plain, key_client_tgs_hex);

	char *tgt_hex = NULL;
	if (!aes256_encrypt_bytes_to_hex_string(key_as_tgs,
	                                        (const unsigned char *)tgt_plain,
	                                        strlen(tgt_plain),
	                                        &tgt_hex))
	{
		free(key_client_tgs_hex);
		free(key_as_tgs);
		free(tgt_plain);
		fprintf(stderr, "Failed to encrypt TGT\n");
		return EXIT_FAILURE;
	}
	free(key_as_tgs);
	free(tgt_plain);

	/* STEP 6: build and encrypt AS_REP */
	size_t as_rep_plain_len = 32 + strlen(tgt_hex);
	unsigned char *as_rep_plain = malloc(as_rep_plain_len);
	if (!as_rep_plain)
	{
		free(key_client_tgs_hex);
		free(tgt_hex);
		fprintf(stderr, "Memory allocation failed\n");
		return EXIT_FAILURE;
	}

	memcpy(as_rep_plain, key_client_tgs, 32);
	memcpy(as_rep_plain + 32, tgt_hex, strlen(tgt_hex));

	unsigned char *as_rep_cipher = NULL;
	int as_rep_cipher_len = 0;
	if (!aes256_ecb_encrypt(key_client_as,
	                        as_rep_plain,
	                        (int)as_rep_plain_len,
	                        &as_rep_cipher,
	                        &as_rep_cipher_len))
	{
		free(key_client_tgs_hex);
		free(tgt_hex);
		free(as_rep_plain);
		fprintf(stderr, "Failed to encrypt AS_REP\n");
		return EXIT_FAILURE;
	}

	if (!write_hex_file("AS_REP.txt", as_rep_cipher, (size_t)as_rep_cipher_len))
	{
		free(key_client_tgs_hex);
		free(tgt_hex);
		free(as_rep_plain);
		free(as_rep_cipher);
		fprintf(stderr, "Failed to write AS_REP.txt\n");
		return EXIT_FAILURE;
	}

	free(key_client_tgs_hex);
	free(tgt_hex);
	free(as_rep_plain);
	free(as_rep_cipher);

	return EXIT_SUCCESS;
}