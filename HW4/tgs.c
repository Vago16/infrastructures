#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/rand.h>

#include "RequiredFunctions.c"

int main(int argc, char *argv[]) {
	if (argc != 6) {
		fprintf(stderr,
		        "Usage: %s <TGS_REQ> <Key_AS_TGS> <Key_Client_TGS> <Key_Client_App> <Key_TGS_App>\n",
		        argv[0]);
		return EXIT_FAILURE;
	}

	const char *tgs_req_path        = argv[1];
	const char *key_as_tgs_path     = argv[2];
	const char *key_client_tgs_path = argv[3];
	const char *key_client_app_path = argv[4];
	const char *key_tgs_app_path    = argv[5];

	/* STEP 0: wait for TGS request */
	if (!file_exists(tgs_req_path)) {
		printf("TGS_REQ not created\n");
		return EXIT_SUCCESS;
	}

	printf("TGS_REQ received\n");

	/* STEP 1: read and decrypt TGT */
	char *tgt_hex = read_line(tgs_req_path, 1);
	char *auth_client_tgs_hex = read_line(tgs_req_path, 2);

	if (!tgt_hex || !auth_client_tgs_hex) {
		free(tgt_hex);
		free(auth_client_tgs_hex);
		fprintf(stderr, "Failed to read TGS_REQ.txt\n");
		return EXIT_FAILURE;
	}

	unsigned char *key_as_tgs = NULL;
	size_t key_as_tgs_len = 0;
	if (!read_hex_file_bytes(key_as_tgs_path, &key_as_tgs, &key_as_tgs_len)) {
		free(tgt_hex);
		free(auth_client_tgs_hex);
		fprintf(stderr, "Failed to read Key_AS_TGS\n");
		return EXIT_FAILURE;
	}
	if (key_as_tgs_len != 32) {
		free(tgt_hex);
		free(auth_client_tgs_hex);
		free(key_as_tgs);
		fprintf(stderr, "Key_AS_TGS length is not 32 bytes\n");
		return EXIT_FAILURE;
	}

	unsigned char *tgt_plain_bytes = NULL;
	size_t tgt_plain_len = 0;
	if (!aes256_decrypt_hex_string_to_bytes(key_as_tgs, tgt_hex,
	                                        &tgt_plain_bytes, &tgt_plain_len)) {
		free(tgt_hex);
		free(auth_client_tgs_hex);
		free(key_as_tgs);
		fprintf(stderr, "Failed to decrypt TGT\n");
		return EXIT_FAILURE;
	}
	free(key_as_tgs);

	char *tgt_plain = malloc(tgt_plain_len + 1);
	if (!tgt_plain) {
		free(tgt_hex);
		free(auth_client_tgs_hex);
		free(tgt_plain_bytes);
		fprintf(stderr, "Memory allocation failed\n");
		return EXIT_FAILURE;
	}
	memcpy(tgt_plain, tgt_plain_bytes, tgt_plain_len);
	tgt_plain[tgt_plain_len] = '\0';
	free(tgt_plain_bytes);

	/* STEP 2: parse clientID and Key_Client_TGS from TGT */
	if (tgt_plain_len < 64) {
		free(tgt_hex);
		free(auth_client_tgs_hex);
		free(tgt_plain);
		fprintf(stderr, "Decrypted TGT is too short\n");
		return EXIT_FAILURE;
	}

	size_t client_id_len = tgt_plain_len - 64;
	char *client_id = malloc(client_id_len + 1);
	char *key_client_tgs_hex = malloc(65);
	if (!client_id || !key_client_tgs_hex) {
		free(tgt_hex);
		free(auth_client_tgs_hex);
		free(tgt_plain);
		free(client_id);
		free(key_client_tgs_hex);
		fprintf(stderr, "Memory allocation failed\n");
		return EXIT_FAILURE;
	}

	memcpy(client_id, tgt_plain, client_id_len);
	client_id[client_id_len] = '\0';

	memcpy(key_client_tgs_hex, tgt_plain + client_id_len, 64);
	key_client_tgs_hex[64] = '\0';
	free(tgt_plain);

	unsigned char *key_client_tgs = NULL;
	size_t key_client_tgs_len = 0;
	if (!hex_to_bytes(key_client_tgs_hex, &key_client_tgs, &key_client_tgs_len)) {
		free(tgt_hex);
		free(auth_client_tgs_hex);
		free(client_id);
		free(key_client_tgs_hex);
		fprintf(stderr, "Failed to parse Key_Client_TGS from TGT\n");
		return EXIT_FAILURE;
	}
	free(key_client_tgs_hex);

	if (key_client_tgs_len != 32) {
		free(tgt_hex);
		free(auth_client_tgs_hex);
		free(client_id);
		free(key_client_tgs);
		fprintf(stderr, "Parsed Key_Client_TGS is not 32 bytes\n");
		return EXIT_FAILURE;
	}

	/* Optional consistency check against file */
	unsigned char *key_client_tgs_ref = NULL;
	size_t key_client_tgs_ref_len = 0;
	if (!read_hex_file_bytes(key_client_tgs_path, &key_client_tgs_ref, &key_client_tgs_ref_len)) {
		free(tgt_hex);
		free(auth_client_tgs_hex);
		free(client_id);
		free(key_client_tgs);
		fprintf(stderr, "Failed to read Key_Client_TGS.txt\n");
		return EXIT_FAILURE;
	}
	if (key_client_tgs_ref_len != 32 || memcmp(key_client_tgs, key_client_tgs_ref, 32) != 0) {
		free(tgt_hex);
		free(auth_client_tgs_hex);
		free(client_id);
		free(key_client_tgs);
		free(key_client_tgs_ref);
		fprintf(stderr, "Key_Client_TGS mismatch\n");
		return EXIT_FAILURE;
	}
	free(key_client_tgs_ref);

	/* STEP 3: verify client authenticator */
	unsigned char *auth_plain = NULL;
	size_t auth_plain_len = 0;
	if (!aes256_decrypt_hex_string_to_bytes(key_client_tgs, auth_client_tgs_hex,
	                                        &auth_plain, &auth_plain_len)) {
		free(tgt_hex);
		free(auth_client_tgs_hex);
		free(client_id);
		free(key_client_tgs);
		fprintf(stderr, "Failed to decrypt Auth_Client_TGS\n");
		return EXIT_FAILURE;
	}
	free(auth_client_tgs_hex);

	char *auth_client_id = malloc(auth_plain_len + 1);
	if (!auth_client_id) {
		free(tgt_hex);
		free(client_id);
		free(key_client_tgs);
		free(auth_plain);
		fprintf(stderr, "Memory allocation failed\n");
		return EXIT_FAILURE;
	}
	memcpy(auth_client_id, auth_plain, auth_plain_len);
	auth_client_id[auth_plain_len] = '\0';
	free(auth_plain);

	/* For this demo, decryption success is enough, but matching helps */
	if (strcmp(auth_client_id, client_id) != 0) {
		free(tgt_hex);
		free(client_id);
		free(key_client_tgs);
		free(auth_client_id);
		fprintf(stderr, "Authenticator client ID mismatch\n");
		return EXIT_FAILURE;
	}
	free(auth_client_id);

	/* STEP 4: load Key_Client_App */
	unsigned char *key_client_app = NULL;
	size_t key_client_app_len = 0;
	if (!read_hex_file_bytes(key_client_app_path, &key_client_app, &key_client_app_len)) {
		free(tgt_hex);
		free(client_id);
		free(key_client_tgs);
		fprintf(stderr, "Failed to read Key_Client_App.txt\n");
		return EXIT_FAILURE;
	}
	if (key_client_app_len != 32) {
		free(tgt_hex);
		free(client_id);
		free(key_client_tgs);
		free(key_client_app);
		fprintf(stderr, "Key_Client_App length is not 32 bytes\n");
		return EXIT_FAILURE;
	}

	char *key_client_app_hex = bytes_to_hex(key_client_app, key_client_app_len);
	if (!key_client_app_hex) {
		free(tgt_hex);
		free(client_id);
		free(key_client_tgs);
		free(key_client_app);
		fprintf(stderr, "Failed to encode Key_Client_App as hex\n");
		return EXIT_FAILURE;
	}

	/* STEP 5: build and encrypt Ticket_App */
	unsigned char *key_tgs_app = NULL;
	size_t key_tgs_app_len = 0;
	if (!read_hex_file_bytes(key_tgs_app_path, &key_tgs_app, &key_tgs_app_len)) {
		free(tgt_hex);
		free(client_id);
		free(key_client_tgs);
		free(key_client_app);
		free(key_client_app_hex);
		fprintf(stderr, "Failed to read Key_TGS_App.txt\n");
		return EXIT_FAILURE;
	}
	if (key_tgs_app_len != 32) {
		free(tgt_hex);
		free(client_id);
		free(key_client_tgs);
		free(key_client_app);
		free(key_client_app_hex);
		free(key_tgs_app);
		fprintf(stderr, "Key_TGS_App length is not 32 bytes\n");
		return EXIT_FAILURE;
	}

	size_t ticket_app_plain_len = strlen(client_id) + strlen(key_client_app_hex);
	char *ticket_app_plain = malloc(ticket_app_plain_len + 1);
	if (!ticket_app_plain) {
		free(tgt_hex);
		free(client_id);
		free(key_client_tgs);
		free(key_client_app);
		free(key_client_app_hex);
		free(key_tgs_app);
		fprintf(stderr, "Memory allocation failed\n");
		return EXIT_FAILURE;
	}

	strcpy(ticket_app_plain, client_id);
	strcat(ticket_app_plain, key_client_app_hex);

	char *ticket_app_hex = NULL;
	if (!aes256_encrypt_bytes_to_hex_string(key_tgs_app,
	                                        (const unsigned char *)ticket_app_plain,
	                                        strlen(ticket_app_plain),
	                                        &ticket_app_hex)) {
		free(tgt_hex);
		free(client_id);
		free(key_client_tgs);
		free(key_client_app);
		free(key_client_app_hex);
		free(key_tgs_app);
		free(ticket_app_plain);
		fprintf(stderr, "Failed to encrypt Ticket_App\n");
		return EXIT_FAILURE;
	}

	free(key_tgs_app);
	free(ticket_app_plain);

	/* STEP 6: encrypt Key_Client_App hex under Key_Client_TGS */
	char *enc_key_client_app_hex = NULL;
	if (!aes256_encrypt_bytes_to_hex_string(key_client_tgs,
	                                        (const unsigned char *)key_client_app_hex,
	                                        strlen(key_client_app_hex),
	                                        &enc_key_client_app_hex)) {
		free(tgt_hex);
		free(client_id);
		free(key_client_tgs);
		free(key_client_app);
		free(key_client_app_hex);
		free(ticket_app_hex);
		fprintf(stderr, "Failed to encrypt Key_Client_App for client\n");
		return EXIT_FAILURE;
	}

	/* STEP 7: write TGS_REP.txt */
	if (!write_text_lines("TGS_REP.txt", ticket_app_hex, enc_key_client_app_hex, NULL)) {
		free(tgt_hex);
		free(client_id);
		free(key_client_tgs);
		free(key_client_app);
		free(key_client_app_hex);
		free(ticket_app_hex);
		free(enc_key_client_app_hex);
		fprintf(stderr, "Failed to write TGS_REP.txt\n");
		return EXIT_FAILURE;
	}

	free(tgt_hex);
	free(client_id);
	free(key_client_tgs);
	free(key_client_app);
	free(key_client_app_hex);
	free(ticket_app_hex);
	free(enc_key_client_app_hex);

	return EXIT_SUCCESS;
}