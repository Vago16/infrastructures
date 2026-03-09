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
	/* TODO:
	 *  - Check existence of:
	 *        client_temp_sk_path
	 *        client_temp_pk_path
	 *  - Print an error and exit on failure
	 */

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
	/* TODO:
	 *  - Use an ECDSA signing helper
	 *  - Sign the CONTENTS of client_temp_pk_path
	 *  - Write the signature in hex format to:
	 *        "Client_Signature.txt"
	 */

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
	/* TODO:
	 *  - Perform ECDH using the two key files
	 *  - Hash the shared secret using SHA-256
	 *  - Read "Key_Client_AS.txt" (hex)
	 *  - Compare values byte-for-byte
	 */

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
	/* TODO:
	 *  - AES-decrypt AS_REP.txt using Key_Client_AS
	 *  - Copy first 32 bytes → key_client_tgs
	 *  - Remaining bytes → TGT (hex string)
	 */

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
	/* TODO:
	 *  - Check existence of "TGS_REQ.txt"
	 *  - If missing:
	 *      - Encrypt string "Client" using Key_Client_TGS
	 *      - Write all three required lines in order
	 */

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
	/* TODO:
	 *  - Encrypt string "Client" using Key_Client_App
	 *  - Read Ticket_App from TGS_REP.txt (line 1)
	 *  - Write both values to "APP_REQ.txt"
	 */

	return EXIT_SUCCESS;
}