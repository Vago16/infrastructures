#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/rand.h>

/*
 * ============================================================
 * Kerberos Client (File-Based Demo) — ASSIGNMENT TEMPLATE
 * ============================================================
 *
 * IMPORTANT:
 *  - You MUST read from and write to files using the EXACT
 *    filenames specified in this template.
 *  - Do NOT rename files or change their formats.
 *  - The grading scripts rely strictly on these filenames.
 *
 * This program implements the CLIENT SIDE of a simplified
 * Kerberos protocol using files for message passing.
 *
 * The client program is executed multiple times by an
 * external script and must correctly handle different
 * protocol phases depending on which files already exist.
 *
 * ------------------------------------------------------------
 * PROTOCOL PHASES IMPLEMENTED BY THIS CLIENT:
 *
 * 1) AS phase   (Authentication Server)
 * 2) TGS_REQ    (Ticket Granting Service Request)
 * 3) APP_REQ    (Application Server Request)
 *
 * Cryptographic primitives used conceptually:
 *  - ECDSA signatures
 *  - ECDH key agreement
 *  - SHA-256 key derivation
 *  - AES-256 encryption/decryption
 *
 * You are provided helper functions in:
 *      RequiredFunctions.c
 * Study them carefully before implementing this file.
 *
 * ============================================================
 */

#include "RequiredFunctions.c"

int main(int argc, char *argv[]) {

	/* ------------------------------------------------------------
	 * Command-line arguments:
	 *
	 * argv[1] : path to Client temporary private key file
	 * argv[2] : path to Client temporary public key file
	 * argv[3] : path to AS temporary public key file
	 *
	 * These files MUST already exist. Do NOT generate keys here.
	 * ------------------------------------------------------------
	 */
	if (argc != 4) {
		fprintf(stderr,
		        "Usage: %s <Client_temp_SK> <Client_temp_PK> <AS_temp_PK>\n",
		        argv[0]);
		return EXIT_FAILURE;
	}

	const char *client_temp_sk_path = argv[1];
	const char *client_temp_pk_path = argv[2];
	const char *as_temp_pk_path     = argv[3];

	/* Buffers for symmetric keys derived during Kerberos */
	unsigned char key_client_as[32];
	unsigned char key_client_tgs[32];
	unsigned char key_client_app[32];

	/* ------------------------------------------------------------
	 * STEP 0: Verify required client temporary key files exist
	 *
	 * The client must already possess a temporary EC key pair.
	 * If either file is missing, abort immediately.
	 * ------------------------------------------------------------
	 */
	/* 
	 *  - Check existence of:
	 *        client_temp_sk_path
	 *        client_temp_pk_path
	 *  - Print an error and exit on failure
	 */
	if (!file_exists(client_temp_sk_path) || !file_exists(client_temp_pk_path)) {
		fprintf(stderr, "Error: One or both temporary key files missing\n");
		return EXIT_FAILURE;
	}

	/* ------------------------------------------------------------
	 * STEP 1: Sign Client temporary public key
	 *
	 * The client authenticates itself to the AS by signing its
	 * temporary public key using its long-term private key.
	 *
	 * INPUT:
	 *  - Client_SK.txt          (long-term client private key)
	 *  - client_temp_pk_path    (temporary public key)
	 *
	 * OUTPUT (must always be regenerated):
	 *  - Client_Signature.txt   (hex-encoded ECDSA signature)
	 *
	 * NOTE:
	 *  - Even if the file already exists, regenerate it.
	 * ------------------------------------------------------------
	 */
	/* 
	 *  - Use an ECDSA signing helper
	 *  - Sign the CONTENTS of client_temp_pk_path
	 *  - Write the signature in hex format to:
	 *        "Client_Signature.txt"
	 */
	if (!ecdsa_sign_file_to_hex("Client_SK.txt", client_temp_pk_path, "Client_Signature.txt")) {
		fprintf(stderr, "Client Error: Signing Client temporary public key failed\n");
		return EXIT_FAILURE;
	}
	 

	/* ------------------------------------------------------------
	 * STEP 2: Wait for AS response
	 *
	 * The Authentication Server writes AS_REP.txt when ready.
	 * If it does not yet exist, exit gracefully.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Check if "AS_REP.txt" exists
	 *  - If not, print a status message and exit SUCCESSFULLY
	 */
	if (!file_exists("AS_REP.txt")) {
		printf("Client Error: AS_REP does not yet exist\n");
		return EXIT_SUCCESS;
	}

	/* ------------------------------------------------------------
	 * STEP 3: Derive Key_Client_AS
	 *
	 * The client derives a shared secret with the AS using ECDH:
	 *
	 *      shared = ECDH(Client_temp_SK, AS_temp_PK)
	 *
	 * Then derives a symmetric key:
	 *
	 *      Key_Client_AS = SHA256(shared)
	 *
	 * This key MUST match the reference key stored in:
	 *      "Key_Client_AS.txt"
	 *
	 * Abort if the derived key does not match.
	 * ------------------------------------------------------------
	 */
	/* 
	 *  - Perform ECDH using the two key files
	 *  - Hash the shared secret using SHA-256
	 *  - Read "Key_Client_AS.txt" (hex)
	 *  - Compare values byte-for-byte
	 */
	 //perform ECDH
	unsigned char *shared_secret = NULL;
	size_t shared_len = 0;

	if(!ecdh_shared_secret_files(client_temp_sk_path, as_temp_pk_path, &shared_secret, &shared_len)) {
		fprintf(stderr, "CLient Error: ECDH failed\n");
		return EXIT_FAILURE;
	}

	 //hash shared secret
	if (!sha256_bytes(shared_secret, shared_len, key_client_as)) {
		fprintf(stderr, "Client Erorr: SHA-256 hash failed\n");
		free(shared_secret);
		return EXIT_FAILURE;
	}

	 //read ref key in Key_Client_AS.txt
	unsigned char *ref_key = NULL;
	size_t ref_len = 0;

	if (!read_hex_file_bytes("Key_Client_AS.txt", &ref_key, &ref_len) || ref_len != 32) {
		fprintf(stderr, "Client Error: Failed to read Key_Client_AS.txt or wrong length\n");
		return EXIT_FAILURE;
	}

	 //compare
	if (memcmp(key_client_as, ref_key, 32) != 0) {
		fprintf(stderr, "Client Error: Keys from Client_temp_Sk.txt and AS_temp_PK.txt do not match\n");
		free(ref_key);
		return EXIT_FAILURE;
	}

	 //cleanup
	free(shared_secret);
	free(ref_key);
	/* ------------------------------------------------------------
	 * STEP 4: Decrypt AS_REP
	 *
	 * AS_REP.txt is AES-256 encrypted using Key_Client_AS.
	 *
	 * After decryption, the plaintext contains:
	 *
	 *   [ 32 bytes Key_Client_TGS ] ||
	 *   [ ASCII hex string of TGT ]
	 *
	 * Extract BOTH values.
	 * ------------------------------------------------------------
	 */
	/* 
	 *  - AES-decrypt AS_REP.txt using Key_Client_AS
	 *  - Copy first 32 bytes → key_client_tgs
	 *  - Remaining bytes → TGT (hex string)
	 */
	 //Read and decrypt ciphertext using Key_Client_AS
	unsigned char *cipher = NULL;
	size_t cipher_len = 0;

	if (!read_hex_file_bytes("AS_REP.txt", &cipher, &cipher_len)) {
		fprintf(stderr, "Client Error: Failed to read AS_REP.txt\n");
		return EXIT_FAILURE;
	}

	unsigned char *plain = NULL;	//to hold key_client_tgs(first 32 bytes)
	size_t plain_len = 0;

	if (!aes256_ecb_decrypt(cipher, cipher_len, key_client_as, &plain, &plain_len)) {
		fprintf(stderr, "Client Error: Failed to decrypt AS_REP ciphertext\n");
		free(cipher);
		return EXIT_FAILURE;
	}

	free(cipher);

	 //Copy first 32 bytes → key_client_tgs
	memcpy(key_client_tgs, plain, 32);

	if (!write_hex_file("Key_Client_TGS.txt", key_client_tgs, 32)) {
		fprintf(stderr, "Client Error: Failed to write hex to Key_Client_TGS.txt\n");
		return EXIT_FAILURE;
	}

	 //Remaining bytes → TGT (hex string)
	size_t tgt_len = plain_len - 32;
	char *tgt_hex = malloc(tgt_len + 1);

	memcpy(tgt_hex, plain + 32, tgt_len);
	tgt_hex[tgt_len] = '\0';

	write_text_file("TGT.txt", tgt_hex);

	 //cleanup
	free(plain);
	free(tgt_hex);
	/* ------------------------------------------------------------
	 * STEP 5: Create TGS_REQ (only once)
	 *
	 * If TGS_REQ.txt does NOT already exist:
	 *
	 *   Auth_Client_TGS = AES(Key_Client_TGS, "Client")
	 *
	 * Write TGS_REQ.txt with EXACTLY THREE lines:
	 *
	 *   line 1: TGT hex
	 *   line 2: Auth_Client_TGS hex
	 *   line 3: Service ID string (plain text): "Service"
	 *
	 * ------------------------------------------------------------
	 */
	/* 
	 *  - Check existence of "TGS_REQ.txt"
	 *  - If missing:
	 *      - Encrypt string "Client" using Key_Client_TGS
	 *      - Write all three required lines in order
	 */
	if (!file_exists("TGS_REQ.txt")) {
		char *tgt_hex = read_line("TGT.txt", 1);
		if (!tgt_hex) {
			fprintf(stderr, "Client Error: Failed to read TGT.txt\n");
			return EXIT_FAILURE;
		}
	
	char *auth_hex = NULL;
    const char *auth_plain = "Client";
    if (!aes256_encrypt_bytes_to_hex_string(key_client_tgs, (unsigned char *)auth_plain, strlen(auth_plain), &auth_hex)) {
        fprintf(stderr, "Client Error: Failed to create Auth_Client_TGS\n");
        free(tgt_hex);
        return EXIT_FAILURE;
    }

	if (!write_text_lines("TGS_REQ.txt", tgt_hex, auth_hex, "Service")) {
        fprintf(stderr, "Client Error: Failed to write TGS_REQ.txt\n");
        free(tgt_hex);
        free(auth_hex);
        return EXIT_FAILURE;
    }

	//cleanup
	free(tgt_hex);
    free(auth_hex);
	}

	/* ------------------------------------------------------------
	 * STEP 6: Wait for TGS response
	 *
	 * TGS writes "TGS_REP.txt" when ready.
	 * If missing, exit gracefully.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Check existence of "TGS_REP.txt"
	 *  - If not present, print status and exit SUCCESSFULLY
	 */
	if (!file_exists("TGS_REP.txt")) {
		printf("Client Warning: TGS_REP not present\n");
		return EXIT_SUCCESS;
	} 

	/* ------------------------------------------------------------
	 * STEP 7: Recover Key_Client_App
	 *
	 * TGS_REP.txt format:
	 *
	 *   line 1: Ticket_App (hex)
	 *   line 2: enc_key_client_app (hex, AES under Key_Client_TGS)
	 *
	 * Decrypt line 2 using Key_Client_TGS to recover:
	 *      Key_Client_App (hex → 32 bytes)
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Read second line of TGS_REP.txt
	 *  - AES-decrypt using Key_Client_TGS
	 *  - Convert hex string to raw bytes
	 *  - Store exactly 32 bytes in key_client_app
	 */
	unsigned char *cipher2 = NULL;
	size_t cipher2_len = 0;

	 //read TGS_REP.txt
	char *enc_key_hex = read_line("TGS_REP.txt", 2);
	if (!enc_key_hex) {
		fprintf(stderr, "Client Error: Failed to read encrypted Key_Client_App\n");
		return EXIT_FAILURE;
	}

	if (!hex_to_bytes(enc_key_hex, &cipher2, &cipher2_len)) {
		fprintf(stderr, "Client Error: Failed to decode hex\n");
		free(enc_key_hex);
		return EXIT_FAILURE;
	}

	 // AES-decrypt with Key_Client_TGS
	unsigned char *plain2 = NULL;
	size_t plain2_len = 0;

	if (!aes256_ecb_decrypt(cipher, cipher_len, key_client_tgs, &plain2, &plain2_len)) {
		fprintf(stderr, "Error: Failed to decrypt TGS_REP\n");
		free(cipher);
		return EXIT_FAILURE;
	}

	memcpy(key_client_app, plain2, 32);

	char *ticket_hex = read_line("TGS_REP.txt", 1);
	if (!ticket_hex) {
		fprintf(stderr, "Client Error: Failed to read Ticket_App\n");
		return EXIT_FAILURE;
	}

	if (!write_hex_file("Key_Client_App.txt", key_client_app, 32)) {
		fprintf(stderr, "CLient Error: Failed to write Key_Client_App.txt\n");
		free(ticket_hex);
		return EXIT_FAILURE;
	}

	if (!write_text_file("Service_Ticket.txt", ticket_hex)) {
		fprintf(stderr, "Client Error: Failed to write Service_Ticket.txt\n");
		free(ticket_hex);
		return EXIT_FAILURE;
	}

	//cleanup
	free(cipher2);
	free(ticket_hex);
	free(plain2);
	free(enc_key_hex);
	/* ------------------------------------------------------------
	 * STEP 8: Create APP_REQ
	 *
	 *   Auth_Client_App = AES(Key_Client_App, "Client")
	 *
	 * Write APP_REQ.txt with EXACTLY TWO lines:
	 *
	 *   line 1: Ticket_App hex
	 *   line 2: Auth_Client_App hex
	 *
	 * ------------------------------------------------------------
	 */
	/*
	 *  - Encrypt string "Client" using Key_Client_App
	 *  - Read Ticket_App from TGS_REP.txt (line 1)
	 *  - Write both values to "APP_REQ.txt"
	 */
	/* Encrypt "Client" using Key_Client_App */
	char *auth_hex = NULL;

	if (!aes256_encrypt_bytes_to_hex_string(
			key_client_app,
			(unsigned char *)"Client",
			strlen("Client"),
			&auth_hex)) {

		fprintf(stderr, "Client Error: Failed to create Auth_Client_App\n");
		return EXIT_FAILURE;
	}

	FILE *f_out = fopen("APP_REQ.txt", "w");
	if (!f_out) {
		fprintf(stderr, "Client Error: Could not create APP_REQ.txt\n");
		return EXIT_FAILURE;
	}

	fprintf(f_out, "%s\n%s\n", ticket_hex, auth_hex);

	fclose(f_out);
	
	//cleanup
	free(auth_hex);
	free(ticket_hex);

	return EXIT_SUCCESS;
}