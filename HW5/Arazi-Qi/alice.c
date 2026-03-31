/*
 * alice.c — Node Alice for Arazi–Qi Key Exchange (ECDLP)
 *
 * ============================
 * ASSIGNMENT TEMPLATE VERSION
 * ============================
 *
 * STUDENT TASK:
 *   Implement Alice’s online (ephemeral) phase and shared key computation
 *   for the Arazi–Qi identity-based authenticated Diffie–Hellman protocol.
 *
 *   You MUST NOT change:
 *     - File names
 *     - Variable names
 *     - Identity strings
 *     - Function signatures
 *
 *   You MUST replace all TODO sections with working code
 *   using the specified helper functions and OpenSSL APIs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "RequiredFunctions.h"

/* Fixed identity strings */
static const char *ID_A = "alice@example.com";
static const char *ID_B = "bob@example.com";

int main(int argc, char **argv)
{
	int ret = EXIT_FAILURE;

	/* === Cryptographic context === */
	EC_GROUP *group = NULL;
	BIGNUM *q = NULL;
	const EC_POINT *P = NULL;
	BN_CTX *ctx = NULL;

	/* === Long-term and ephemeral objects === */
	BIGNUM *x_a = NULL;	  /* Alice private key */
	BIGNUM *p_a = NULL;	  /* Alice ephemeral scalar */
	EC_POINT *U_a = NULL; /* Alice public identity point */
	EC_POINT *U_b = NULL; /* Bob public identity point */
	EC_POINT *D = NULL;	  /* CA master public key */
	EC_POINT *E_a = NULL; /* Alice ephemeral public */
	EC_POINT *E_b = NULL; /* Bob ephemeral public */

	EC_POINT *temp1 = NULL;
	EC_POINT *temp2 = NULL;
	EC_POINT *K_ab = NULL;

	BIGNUM *h_B = NULL;
	BIGNUM *tmp = NULL;

	unsigned char *U_bytes = NULL;
	size_t U_len = 0;
	unsigned char *buf = NULL;
	size_t buf_len = 0;

	/* =====================================================
	 * 1. Command-line argument validation
	 * =====================================================
	 *
	 * REQUIRED invocation:
	 *
	 *   ./alice <x_a_file> <U_a_file> <p_a_file> <U_b_file> <D_file>
	 *
	 * ARGUMENTS:
	 *   argv[1] : alice_private_xa.txt
	 *   argv[2] : alice_public_Ua.txt
	 *   argv[3] : alice_ephemeral_pa.txt
	 *   argv[4] : bob_public_Ub.txt
	 *   argv[5] : ca_master_public_D.txt
	 *
	 * ACTION:
	 *   - If argc != 6, print usage and EXIT_FAILURE.
	 */

	if (argc != 6)
	{
		fprintf(stderr,
				"Usage: %s <x_a_file> <U_a_file> <p_a_file> <U_b_file> <D_file>\n",
				argv[0]);
		return EXIT_FAILURE;
	}

	/* =====================================================
	 * 2. Initialize elliptic curve group
	 * =====================================================
	 *
	 * TASK:
	 *   - Initialize EC_GROUP using a named curve
	 *   - Retrieve group order q
	 *
	 * FUNCTION:
	 *   init_group(&group, &q)
	 *
	 * EXIT on failure.
	 */

	// Call init_group(&group, &q)
	if (!init_group(&group, &q)) {
		fprintf(stderr, "Error initializing group\n");
		goto cleanup;
	}

	/* =====================================================
	 * 3. Obtain generator P
	 * =====================================================
	 *
	 * FUNCTION:
	 *   EC_GROUP_get0_generator(group)
	 *
	 * EXIT if P == NULL.
	 */

	// Set P = EC_GROUP_get0_generator(group)
	P = EC_GROUP_get0_generator(group);
	if (!P) {
		fprintf(stderr, "Error getting generator P\n");
		goto cleanup;
	}

	/* =====================================================
	 * 4. Allocate BN_CTX
	 * =====================================================
	 *
	 * FUNCTION:
	 *   BN_CTX_new()
	 *
	 * EXIT if allocation fails.
	 */

	// Allocate ctx
	ctx = BN_CTX_new();
	if (!ctx) {
		fprintf(stderr, "Error allocating BN_CTX\n");
		goto cleanup;
	}

	/* =====================================================
	 * 5. Load Alice and system public parameters
	 * =====================================================
	 *
	 * FILE INPUTS:
	 *   argv[1] : x_a (scalar)
	 *   argv[2] : U_a (EC point)
	 *   argv[4] : U_b (EC point)
	 *   argv[5] : D   (EC point)
	 *
	 * FUNCTIONS:
	 *   read_bn_hex
	 *   EC_POINT_new
	 *   read_point_hex
	 *
	 * EXIT if any file does not exist or parsing fails.
	 */

	// TODO: Read x_a from argv[1]
	// TODO: Allocate U_a, U_b, D using EC_POINT_new
	// TODO: Read U_a from argv[2]
	// TODO: Read U_b from argv[4]
	// TODO: Read D from argv[5]

	/* =====================================================
	 * 6. Load Alice ephemeral scalar p_a
	 * =====================================================
	 *
	 * FILE INPUT:
	 *   argv[3] : alice_ephemeral_pa.txt
	 *
	 * FUNCTION:
	 *   read_bn_hex
	 *
	 * EXIT if missing or invalid.
	 */

	// TODO: Read p_a from argv[3]

	/* =====================================================
	 * 7. Compute Alice ephemeral public E_a
	 * =====================================================
	 *
	 * FORMULA:
	 *   E_a = p_a * P
	 *
	 * FUNCTION:
	 *   EC_POINT_mul
	 *
	 * OUTPUT FILE:
	 *   alice_ephemeral_Ea.txt
	 */

	// TODO: Allocate E_a
	// TODO: Compute E_a = p_a * P
	// TODO: Write alice_ephemeral_Ea.txt

	/* =====================================================
	 * 8. Read Bob ephemeral public E_b (if available)
	 * =====================================================
	 *
	 * FILE INPUT:
	 *   bob_ephemeral_Eb.txt
	 *
	 * FUNCTION:
	 *   read_point_hex
	 *
	 * BEHAVIOR:
	 *   - If file does NOT exist:
	 *       * Print informational message
	 *       * Exit successfully after writing E_a
	 */

	// TODO: Attempt to read bob_ephemeral_Eb.txt into E_b

	/* =====================================================
	 * 9. Compute h_B = H(ID_B || U_b)
	 * =====================================================
	 *
	 * STEPS:
	 *   1. Serialize U_b to bytes
	 *      Function: point_to_bytes
	 *   2. Concatenate ID_B || U_b_bytes
	 *   3. Hash and reduce mod q
	 *      Function: sha256_to_scalar
	 */

	// TODO: Serialize U_b
	// TODO: Build hash buffer
	// TODO: Compute h_B

	/* =====================================================
	 * 10. Compute shared key K_ab
	 * =====================================================
	 *
	 * FORMULA:
	 *
	 *   K_ab =
	 *     x_a * ( H(ID_B||U_b) * U_b + D )
	 *     + p_a * E_b
	 *
	 * FUNCTIONS:
	 *   EC_POINT_mul
	 *   EC_POINT_add
	 *
	 * STEPS:
	 *   temp1 = H * U_b
	 *   temp1 = temp1 + D
	 *   temp2 = x_a * temp1
	 *   temp1 = p_a * E_b
	 *   K_ab  = temp2 + temp1
	 */

	// TODO: Allocate temp1, temp2, K_ab
	// TODO: Compute H * U_b
	// TODO: Add D
	// TODO: Multiply by x_a
	// TODO: Compute p_a * E_b
	// TODO: Add results into K_ab

	/* =====================================================
	 * 11. Write shared key to disk
	 * =====================================================
	 *
	 * OUTPUT FILE:
	 *   alice_shared_key_Kab.txt
	 *
	 * FUNCTION:
	 *   write_point_hex
	 */

	// TODO: Write alice_shared_key_Kab.txt

	printf("[Alice] Shared key K_ab computed and written.\n");
	ret = EXIT_SUCCESS;

	/* =====================================================
	 * 12. Cleanup
	 * =====================================================
	 *
	 * TASK:
	 *   Free ALL allocated objects using:
	 *     BN_free
	 *     EC_POINT_free
	 *     EC_GROUP_free
	 *     BN_CTX_free
	 */

cleanup:
	// TODO: Free all allocated memory

	return ret;
}
