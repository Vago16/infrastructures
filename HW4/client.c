#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/rand.h>

#include "RequiredFunctions.c"

int main(int argc, char *argv[]) {
	if (argc != 4) {
		fprintf(stderr,
		        "Usage: %s <Client_temp_SK> <Client_temp_PK> <AS_temp_PK>\n",
		        argv[0]);
		return EXIT_FAILURE;
	}

	const char *client_temp_sk_path = argv[1];
	const char *client_temp_pk_path = argv[2];
	const char *as_temp_pk_path     = argv[3];

	unsigned char key_client_as[32];
	unsigned char key_client_tgs[32];
	unsigned char key_client_app[32];

	/* STEP 0: check required temp key files */
	if (!file_exists(client_temp_sk_path)) {
		fprintf(stderr, "Missing file: %s\n", client_temp_sk_path);
		return EXIT_FAILURE;
	}
	if (!file_exists(client_temp_pk_path)) {
		fprintf(stderr, "Missing file: %s\n", client_temp_pk_path);
		return EXIT_FAILURE;
	}
	if (!file_exists(as_temp_pk_path)) {
		fprintf(stderr, "Missing file: %s\n", as_temp_pk_path);
		return EXIT_FAILURE;
	}

	/* STEP 1: always regenerate Client_Signature.txt */
	if (!file_exists("Client_SK.txt")) {
		fprintf(stderr, "Missing file: Client_SK.txt\n");
		return EXIT_FAILURE;
	}
	if (!ecdsa_sign_file_to_hex("Client_SK.txt", client_temp_pk_path, "Client_Signature.txt")) {
		fprintf(stderr, "Failed to create Client_Signature.txt\n");
		return EXIT_FAILURE;
	}

	/* STEP 2: wait for AS_REP.txt */
	if (!file_exists("AS_REP.txt")) {
		printf("AS_REP.txt not created yet\n");
		return EXIT_SUCCESS;
	}

	/* STEP 3: derive Key_Client_AS = SHA256(ECDH(Client_temp_SK, AS_temp_PK)) */
	unsigned char *shared_secret = NULL;
	size_t shared_secret_len = 0;
	if (!ecdh_shared_secret_files(client_temp_sk_path, as_temp_pk_path,
	                              &shared_secret, &shared_secret_len)) {
		fprintf(stderr, "Failed to derive ECDH shared secret\n");
		return EXIT_FAILURE;
	}

	if (!sha256_bytes(shared_secret, shared_secret_len, key_client_as)) {
		free(shared_secret);
		fprintf(stderr, "Failed to derive Key_Client_AS\n");
		return EXIT_FAILURE;
	}
	free(shared_secret);

	unsigned char *ref_key_client_as = NULL;
	size_t ref_key_client_as_len = 0;
	if (!read_hex_file_bytes("Key_Client_AS.txt", &ref_key_client_as, &ref_key_client_as_len)) {
		fprintf(stderr, "Failed to read Key_Client_AS.txt\n");
		return EXIT_FAILURE;
	}
	if (ref_key_client_as_len != 32 || memcmp(key_client_as, ref_key_client_as, 32) != 0) {
		free(ref_key_client_as);
		fprintf(stderr, "Derived Key_Client_AS does not match Key_Client_AS.txt\n");
		return EXIT_FAILURE;
	}
	free(ref_key_client_as);

	/* STEP 4: decrypt AS_REP.txt */
	unsigned char *as_rep_plain = NULL;
	size_t as_rep_plain_len = 0;
	if (!aes256_decrypt_hex_file_to_bytes(key_client_as, "AS_REP.txt",
	                                      &as_rep_plain, &as_rep_plain_len)) {
		fprintf(stderr, "Failed to decrypt AS_REP.txt\n");
		return EXIT_FAILURE;
	}
	if (as_rep_plain_len < 33) {
		free(as_rep_plain);
		fprintf(stderr, "AS_REP plaintext too short\n");
		return EXIT_FAILURE;
	}

	memcpy(key_client_tgs, as_rep_plain, 32);

	size_t tgt_len = as_rep_plain_len - 32;
	char *tgt_hex = malloc(tgt_len + 1);
	if (!tgt_hex) {
		free(as_rep_plain);
		fprintf(stderr, "Memory allocation failed\n");
		return EXIT_FAILURE;
	}
	memcpy(tgt_hex, as_rep_plain + 32, tgt_len);
	tgt_hex[tgt_len] = '\0';
	free(as_rep_plain);

	/* STEP 5: create TGS_REQ.txt only if it does not exist */
	if (!file_exists("TGS_REQ.txt")) {
		char *auth_client_tgs_hex = NULL;
		if (!aes256_encrypt_bytes_to_hex_string(key_client_tgs,
		                                        (const unsigned char *)"Client",
		                                        strlen("Client"),
		                                        &auth_client_tgs_hex)) {
			free(tgt_hex);
			fprintf(stderr, "Failed to create Auth_Client_TGS\n");
			return EXIT_FAILURE;
		}

		if (!write_text_lines("TGS_REQ.txt", tgt_hex, auth_client_tgs_hex, "Service")) {
			free(tgt_hex);
			free(auth_client_tgs_hex);
			fprintf(stderr, "Failed to write TGS_REQ.txt\n");
			return EXIT_FAILURE;
		}
		free(auth_client_tgs_hex);
	}

	/* STEP 6: wait for TGS_REP.txt */
	if (!file_exists("TGS_REP.txt")) {
		free(tgt_hex);
		printf("TGS_REP.txt not created yet\n");
		return EXIT_SUCCESS;
	}

	/* STEP 7: recover Key_Client_App from line 2 of TGS_REP.txt */
	char *ticket_app_hex = read_line("TGS_REP.txt", 1);
	char *enc_key_client_app_hex = read_line("TGS_REP.txt", 2);

	if (!ticket_app_hex || !enc_key_client_app_hex) {
		free(tgt_hex);
		free(ticket_app_hex);
		free(enc_key_client_app_hex);
		fprintf(stderr, "Failed to read TGS_REP.txt\n");
		return EXIT_FAILURE;
	}

	unsigned char *key_client_app_hex_plain = NULL;
	size_t key_client_app_hex_plain_len = 0;
	if (!aes256_decrypt_hex_string_to_bytes(key_client_tgs, enc_key_client_app_hex,
	                                        &key_client_app_hex_plain,
	                                        &key_client_app_hex_plain_len)) {
		free(tgt_hex);
		free(ticket_app_hex);
		free(enc_key_client_app_hex);
		fprintf(stderr, "Failed to decrypt enc_key_client_app\n");
		return EXIT_FAILURE;
	}

	char *key_client_app_hex_str = malloc(key_client_app_hex_plain_len + 1);
	if (!key_client_app_hex_str) {
		free(tgt_hex);
		free(ticket_app_hex);
		free(enc_key_client_app_hex);
		free(key_client_app_hex_plain);
		fprintf(stderr, "Memory allocation failed\n");
		return EXIT_FAILURE;
	}
	memcpy(key_client_app_hex_str, key_client_app_hex_plain, key_client_app_hex_plain_len);
	key_client_app_hex_str[key_client_app_hex_plain_len] = '\0';
	free(key_client_app_hex_plain);

	unsigned char *key_client_app_raw = NULL;
	size_t key_client_app_raw_len = 0;
	if (!hex_to_bytes(key_client_app_hex_str, &key_client_app_raw, &key_client_app_raw_len)) {
		free(tgt_hex);
		free(ticket_app_hex);
		free(enc_key_client_app_hex);
		free(key_client_app_hex_str);
		fprintf(stderr, "Failed to parse Key_Client_App hex\n");
		return EXIT_FAILURE;
	}
	free(key_client_app_hex_str);

	if (key_client_app_raw_len != 32) {
		free(tgt_hex);
		free(ticket_app_hex);
		free(enc_key_client_app_hex);
		free(key_client_app_raw);
		fprintf(stderr, "Key_Client_App length is not 32 bytes\n");
		return EXIT_FAILURE;
	}

	memcpy(key_client_app, key_client_app_raw, 32);
	free(key_client_app_raw);
	free(enc_key_client_app_hex);

	/* STEP 8: create APP_REQ.txt */
	char *auth_client_app_hex = NULL;
	if (!aes256_encrypt_bytes_to_hex_string(key_client_app,
	                                        (const unsigned char *)"Client",
	                                        strlen("Client"),
	                                        &auth_client_app_hex)) {
		free(tgt_hex);
		free(ticket_app_hex);
		fprintf(stderr, "Failed to create Auth_Client_App\n");
		return EXIT_FAILURE;
	}

	if (!write_text_lines("APP_REQ.txt", ticket_app_hex, auth_client_app_hex, NULL)) {
		free(tgt_hex);
		free(ticket_app_hex);
		free(auth_client_app_hex);
		fprintf(stderr, "Failed to write APP_REQ.txt\n");
		return EXIT_FAILURE;
	}

	free(tgt_hex);
	free(ticket_app_hex);
	free(auth_client_app_hex);

	return EXIT_SUCCESS;
}