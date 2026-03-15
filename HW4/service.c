#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/rand.h>

#include "RequiredFunctions.c"

int main(int argc, char *argv[]) {
	if (argc != 3) {
		fprintf(stderr,
		        "Usage: %s <APP_REQ file> <Key_TGS_App file>\n",
		        argv[0]);
		return EXIT_FAILURE;
	}

	const char *app_req_path     = argv[1];
	const char *key_tgs_app_path = argv[2];

	/* STEP 0: wait for application request */
	if (!file_exists(app_req_path)) {
		printf("Service not requested yet\n");
		return EXIT_SUCCESS;
	}

	printf("Service requested\n");

	/* STEP 1: load Key_TGS_App */
	unsigned char *key_tgs_app = NULL;
	size_t key_tgs_app_len = 0;
	if (!read_hex_file_bytes(key_tgs_app_path, &key_tgs_app, &key_tgs_app_len)) {
		fprintf(stderr, "Failed to read Key_TGS_App.txt\n");
		return EXIT_FAILURE;
	}
	if (key_tgs_app_len != 32) {
		free(key_tgs_app);
		fprintf(stderr, "Key_TGS_App length is not 32 bytes\n");
		return EXIT_FAILURE;
	}

	/* STEP 2: decrypt Ticket_App */
	char *ticket_app_hex = read_line(app_req_path, 1);
	char *auth_client_app_hex = read_line(app_req_path, 2);

	if (!ticket_app_hex || !auth_client_app_hex) {
		free(key_tgs_app);
		free(ticket_app_hex);
		free(auth_client_app_hex);
		fprintf(stderr, "Failed to read APP_REQ.txt\n");
		return EXIT_FAILURE;
	}

	unsigned char *ticket_app_plain_bytes = NULL;
	size_t ticket_app_plain_len = 0;
	if (!aes256_decrypt_hex_string_to_bytes(key_tgs_app, ticket_app_hex,
	                                        &ticket_app_plain_bytes,
	                                        &ticket_app_plain_len)) {
		free(key_tgs_app);
		free(ticket_app_hex);
		free(auth_client_app_hex);
		fprintf(stderr, "Failed to decrypt Ticket_App\n");
		return EXIT_FAILURE;
	}
	free(key_tgs_app);

	char *ticket_app_plain = malloc(ticket_app_plain_len + 1);
	if (!ticket_app_plain) {
		free(ticket_app_hex);
		free(auth_client_app_hex);
		free(ticket_app_plain_bytes);
		fprintf(stderr, "Memory allocation failed\n");
		return EXIT_FAILURE;
	}
	memcpy(ticket_app_plain, ticket_app_plain_bytes, ticket_app_plain_len);
	ticket_app_plain[ticket_app_plain_len] = '\0';
	free(ticket_app_plain_bytes);

	/* STEP 3: parse clientID_1 and Key_Client_App */
	if (ticket_app_plain_len < 64) {
		free(ticket_app_hex);
		free(auth_client_app_hex);
		free(ticket_app_plain);
		fprintf(stderr, "Decrypted Ticket_App too short\n");
		return EXIT_FAILURE;
	}

	size_t client_id_1_len = ticket_app_plain_len - 64;
	char *client_id_1 = malloc(client_id_1_len + 1);
	char *key_client_app_hex = malloc(65);

	if (!client_id_1 || !key_client_app_hex) {
		free(ticket_app_hex);
		free(auth_client_app_hex);
		free(ticket_app_plain);
		free(client_id_1);
		free(key_client_app_hex);
		fprintf(stderr, "Memory allocation failed\n");
		return EXIT_FAILURE;
	}

	memcpy(client_id_1, ticket_app_plain, client_id_1_len);
	client_id_1[client_id_1_len] = '\0';

	memcpy(key_client_app_hex, ticket_app_plain + client_id_1_len, 64);
	key_client_app_hex[64] = '\0';
	free(ticket_app_plain);

	unsigned char *key_client_app = NULL;
	size_t key_client_app_len = 0;
	if (!hex_to_bytes(key_client_app_hex, &key_client_app, &key_client_app_len)) {
		free(ticket_app_hex);
		free(auth_client_app_hex);
		free(client_id_1);
		free(key_client_app_hex);
		fprintf(stderr, "Failed to parse Key_Client_App\n");
		return EXIT_FAILURE;
	}
	free(key_client_app_hex);

	if (key_client_app_len != 32) {
		free(ticket_app_hex);
		free(auth_client_app_hex);
		free(client_id_1);
		free(key_client_app);
		fprintf(stderr, "Key_Client_App length is not 32 bytes\n");
		return EXIT_FAILURE;
	}

	/* STEP 4: decrypt Auth_Client_App */
	unsigned char *auth_plain = NULL;
	size_t auth_plain_len = 0;
	if (!aes256_decrypt_hex_string_to_bytes(key_client_app, auth_client_app_hex,
	                                        &auth_plain, &auth_plain_len)) {
		free(ticket_app_hex);
		free(auth_client_app_hex);
		free(client_id_1);
		free(key_client_app);
		fprintf(stderr, "Failed to decrypt Auth_Client_App\n");
		return EXIT_FAILURE;
	}

	char *client_id_2 = malloc(auth_plain_len + 1);
	if (!client_id_2) {
		free(ticket_app_hex);
		free(auth_client_app_hex);
		free(client_id_1);
		free(key_client_app);
		free(auth_plain);
		fprintf(stderr, "Memory allocation failed\n");
		return EXIT_FAILURE;
	}
	memcpy(client_id_2, auth_plain, auth_plain_len);
	client_id_2[auth_plain_len] = '\0';
	free(auth_plain);

	/* STEP 5: validate client identity */
	if (strcmp(client_id_1, client_id_2) != 0) {
		free(ticket_app_hex);
		free(auth_client_app_hex);
		free(client_id_1);
		free(key_client_app);
		free(client_id_2);
		fprintf(stderr, "Client identity mismatch\n");
		return EXIT_FAILURE;
	}

	/* STEP 6: write APP_REP.txt */
	FILE *f = fopen("APP_REP.txt", "w");
	if (!f) {
		free(ticket_app_hex);
		free(auth_client_app_hex);
		free(client_id_1);
		free(key_client_app);
		free(client_id_2);
		fprintf(stderr, "Failed to write APP_REP.txt\n");
		return EXIT_FAILURE;
	}
	fprintf(f, "OK\n");
	fclose(f);

	free(ticket_app_hex);
	free(auth_client_app_hex);
	free(client_id_1);
	free(key_client_app);
	free(client_id_2);

	return EXIT_SUCCESS;
}