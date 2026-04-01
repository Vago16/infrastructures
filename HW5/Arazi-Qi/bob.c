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
    ctx = BN_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error allocating BN_CTX\n");
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

    // Read x_b from argv[1]
    if (!read_bn_hex(argv[1], &x_b)) {
        fprintf(stderr, "Error reading x_b\n");
        goto cleanup;
    }

    // Allocate U_b, U_a, D using EC_POINT_new
    U_b = EC_POINT_new(group);
    U_a = EC_POINT_new(group);
    D   = EC_POINT_new(group);

    if (!U_b || !U_a || !D) {
        fprintf(stderr, "Error allocating EC_POINTs\n");
        goto cleanup;
    }

    // Read U_b from argv[2]
    if (!read_point_hex(argv[2], group, &U_b)) {
        fprintf(stderr, "Error reading U_b from argument 2\n");
        goto cleanup;
    }

    // Read U_a from argv[4]
    if (!read_point_hex(argv[4], group, &U_a)) {
        fprintf(stderr, "Error reading U_a from argument 4\n");
        goto cleanup;
    }

    // Read D from argv[5]
    if (!read_point_hex(argv[5], group, &D)) {
        fprintf(stderr, "Error reading D from argument 5\n");
        goto cleanup;
    }

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

    // Read p_b from argv[3]
    if (!read_bn_hex(argv[3], &p_b)) {
        fprintf(stderr, "Error reading p_b\n");
        goto cleanup;
    }

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

    // Allocate E_b
    E_b = EC_POINT_new(group);
    if (!E_b) goto cleanup;

    // Compute E_b = p_b * P
    if (!EC_POINT_mul(group, E_b, NULL, P, p_b, ctx)) {
        fprintf(stderr, "Error computing E_b\n");
        goto cleanup;
    }

    // Write bob_ephemeral_Eb.txt
    if (!write_point_hex("bob_ephemeral_Eb.txt", group, E_b)) {
        fprintf(stderr, "Error writing E_b\n");
        goto cleanup;
    }

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

    // Attempt to read alice_ephemeral_Ea.txt into E_a
    if (!read_point_hex("alice_ephemeral_Ea.txt", group, &E_a)) {
        printf("Alice's ephemeral key not found. Exiting after writing E_b.\n");
        ret = EXIT_SUCCESS;
        goto cleanup;
    }

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

    // Serialize U_a
    if (!point_to_bytes(group, U_a, &U_bytes, &U_len)) {
        fprintf(stderr, "Error serializing U_a\n");
        goto cleanup;
    }

    // Build hash buffer
    size_t id_len = strlen(ID_A);
    buf_len = id_len + U_len;

    buf = malloc(buf_len);
    if (!buf) goto cleanup;

    memcpy(buf, ID_A, id_len);
    memcpy(buf + id_len, U_bytes, U_len);

    // Compute h_A
    if (!sha256_to_scalar(buf, buf_len, q, &h_A)) {
    fprintf(stderr, "Error computing h_A\n");
    goto cleanup;
}

    free(U_bytes); 
    U_bytes = NULL;
    free(buf);
    buf = NULL;

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

    // Allocate temp1, temp2, K_ab
    temp1 = EC_POINT_new(group);
    temp2 = EC_POINT_new(group);
    K_ab  = EC_POINT_new(group);

    if (!temp1 || !temp2 || !K_ab) {
        goto cleanup;
    }

    // Compute H * U_a
    if (!EC_POINT_mul(group, temp1, NULL, U_a, h_A, ctx)) {
        fprintf(stderr, "Error computing h_A * U_a\n");
        goto cleanup;
    }

    // Add D
    if (!EC_POINT_add(group, temp1, temp1, D, ctx)) {
        fprintf(stderr, "Error adding D\n");
        goto cleanup;
    }
    // Multiply by x_b
    if (!EC_POINT_mul(group, temp2, NULL, temp1, x_b, ctx)) {
        fprintf(stderr, "Error computing x_b * temp1\n");
        goto cleanup;
    }

    // Compute p_b * E_a
    if (!EC_POINT_mul(group, temp1, NULL, E_a, p_b, ctx)) {
        fprintf(stderr, "Error computing p_b * E_a\n");
        goto cleanup;
    }

    // TODO: Add results into K_ab
    if (!EC_POINT_add(group, K_ab, temp2, temp1, ctx)) {
        fprintf(stderr, "Error computing K_ab\n");
        goto cleanup;
    }

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

    // Write bob_shared_key_Kab.txt
    if (!write_point_hex("bob_shared_key_Kab.txt", group, K_ab)) {
        fprintf(stderr, "Error writing shared key\n");
        goto cleanup;
    }

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
    // Free all allocated memory
    if (x_b) BN_free(x_b);
    if (p_b) BN_free(p_b);
    if (h_A) BN_free(h_A);
    if (tmp) BN_free(tmp);

    if (U_b) EC_POINT_free(U_b);
    if (U_a) EC_POINT_free(U_a);
    if (D) EC_POINT_free(D);
    if (E_b) EC_POINT_free(E_b);
    if (E_a) EC_POINT_free(E_a);
    if (temp1) EC_POINT_free(temp1);
    if (temp2) EC_POINT_free(temp2);
    if (K_ab) EC_POINT_free(K_ab);

    if (group) EC_GROUP_free(group);
    if (q) BN_free(q);
    if (ctx) BN_CTX_free(ctx);

    if (U_bytes) free(U_bytes);
    if (buf) free(buf);

    return ret;
}
