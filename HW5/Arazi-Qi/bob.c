/*
 * bob.c — Node Bob for Arazi–Qi Key Exchange (ECDLP)
 *
 * ==========================
 * ASSIGNMENT TEMPLATE VERSION
 * ==========================
 *
 * STUDENT TASK:
 *   Implement Bob’s online (ephemeral) phase and shared key computation
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
    BIGNUM *x_b = NULL;   /* Bob private key */
    BIGNUM *p_b = NULL;   /* Bob ephemeral scalar */
    EC_POINT *U_b = NULL; /* Bob public identity point */
    EC_POINT *U_a = NULL; /* Alice public identity point */
    EC_POINT *D = NULL;   /* CA master public key */
    EC_POINT *E_b = NULL; /* Bob ephemeral public */
    EC_POINT *E_a = NULL; /* Alice ephemeral public */

    EC_POINT *temp1 = NULL;
    EC_POINT *temp2 = NULL;
    EC_POINT *K_ab = NULL;

    BIGNUM *h_A = NULL;
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
     *   ./bob <x_b_file> <U_b_file> <p_b_file> <U_a_file> <D_file>
     *
     * ARGUMENTS:
     *   argv[1] : bob_private_xb.txt
     *   argv[2] : bob_public_Ub.txt
     *   argv[3] : bob_ephemeral_pb.txt
     *   argv[4] : alice_public_Ua.txt
     *   argv[5] : ca_master_public_D.txt
     *
     * ACTION:
     *   - If argc != 6, print usage and EXIT_FAILURE.
     */

    if (argc != 6)
    {
        fprintf(stderr,
                "Usage: %s <x_b_file> <U_b_file> <p_b_file> <U_a_file> <D_file>\n",
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
        fprintf(stderr, "Error initializing elliptic curve group\n");
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
    if (!read_bn_hex(argv[1], &x_b)) {
        fprintf(stderr, "Error reading x_b\n");
        goto cleanup;
    }

    U_b = EC_POINT_new(group);
    U_a = EC_POINT_new(group);
    D   = EC_POINT_new(group);

    if (!U_b || !U_a || !D) {
        fprintf(stderr, "Error allocating EC_POINTs\n");
        goto cleanup;
    }

    if (!read_point_hex(argv[2], group, &U_b)) {
        fprintf(stderr, "Error reading U_b\n");
        goto cleanup;
    }

    if (!read_point_hex(argv[4], group, &U_a)) {
        fprintf(stderr, "Error reading U_a\n");
        goto cleanup;
    }

    if (!read_point_hex(argv[5], group, &D)) {
        fprintf(stderr, "Error reading D\n");
        goto cleanup;
    }

    /* =====================================================
     * 5. Load Bob and system public parameters
     * =====================================================
     *
     * FILE INPUTS:
     *   argv[1] : x_b (scalar)
     *   argv[2] : U_b (EC point)
     *   argv[4] : U_a (EC point)
     *   argv[5] : D   (EC point)
     *
     * FUNCTIONS:
     *   read_bn_hex
     *   EC_POINT_new
     *   read_point_hex
     *
     * EXIT if any file does not exist or parsing fails.
     */

    // TODO: Read x_b from argv[1]
    // TODO: Allocate U_b, U_a, D using EC_POINT_new
    // TODO: Read U_b from argv[2]
    // TODO: Read U_a from argv[4]
    // TODO: Read D from argv[5]

    /* =====================================================
     * 6. Load Bob ephemeral scalar p_b
     * =====================================================
     *
     * FILE INPUT:
     *   argv[3] : bob_ephemeral_pb.txt
     *
     * FUNCTION:
     *   read_bn_hex
     *
     * EXIT if missing or invalid.
     */

    // TODO: Read p_b from argv[3]

    /* =====================================================
     * 7. Compute Bob ephemeral public E_b
     * =====================================================
     *
     * FORMULA:
     *   E_b = p_b * P
     *
     * FUNCTION:
     *   EC_POINT_mul
     *
     * OUTPUT FILE:
     *   bob_ephemeral_Eb.txt
     */

    // TODO: Allocate E_b
    // TODO: Compute E_b = p_b * P
    // TODO: Write bob_ephemeral_Eb.txt

    /* =====================================================
     * 8. Read Alice ephemeral public E_a (if available)
     * =====================================================
     *
     * FILE INPUT:
     *   alice_ephemeral_Ea.txt
     *
     * FUNCTION:
     *   read_point_hex
     *
     * BEHAVIOR:
     *   - If file does NOT exist:
     *       * Print informational message
     *       * Exit successfully after writing E_b
     */

    // TODO: Attempt to read alice_ephemeral_Ea.txt into E_a

    /* =====================================================
     * 9. Compute h_A = H(ID_A || U_a)
     * =====================================================
     *
     * STEPS:
     *   1. Serialize U_a to bytes
     *      Function: point_to_bytes
     *   2. Concatenate ID_A || U_a_bytes
     *   3. Hash and reduce mod q
     *      Function: sha256_to_scalar
     */

    // TODO: Serialize U_a
    // TODO: Build hash buffer
    // TODO: Compute h_A

    /* =====================================================
     * 10. Compute shared key K_ab
     * =====================================================
     *
     * FORMULA:
     *
     *   K_ab =
     *     x_b * ( H(ID_A||U_a) * U_a + D )
     *     + p_b * E_a
     *
     * FUNCTIONS:
     *   EC_POINT_mul
     *   EC_POINT_add
     *
     * STEPS:
     *   temp1 = H * U_a
     *   temp1 = temp1 + D
     *   temp2 = x_b * temp1
     *   temp1 = p_b * E_a
     *   K_ab  = temp2 + temp1
     */

    // TODO: Allocate temp1, temp2, K_ab
    // TODO: Compute H * U_a
    // TODO: Add D
    // TODO: Multiply by x_b
    // TODO: Compute p_b * E_a
    // TODO: Add results into K_ab

    /* =====================================================
     * 11. Write shared key to disk
     * =====================================================
     *
     * OUTPUT FILE:
     *   bob_shared_key_Kab.txt
     *
     * FUNCTION:
     *   write_point_hex
     */

    // TODO: Write bob_shared_key_Kab.txt

    printf("[Bob] Shared key K_ab computed and written.\n");
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
