/*
 * signer1.c — Level 1 Signer (ID_1) for Schnorr-HIBS
 *
 * ASSIGNMENT TEMPLATE
 *
 * ROLE:
 *   Implement HIBS.Extract for hierarchy level k = 1.
 *   This program derives the private key for ID_1 from the PKG master secret.
 *
 * INPUT FILES:
 *   - ID1.txt            : contains identity string ID_1
 *   - signer1_b1.txt     : contains random scalar b1 (hex)
 *   - msk.txt            : contains master secret x (hex)
 *
 * OUTPUT FILES:
 *   - sk_ID1.txt         : private key for ID_1 (hex scalar)
 *   - Q_ID1.txt          : public delegation point (hex EC point)
 *
 * REQUIRED CRYPTOGRAPHIC RELATION:
 *   sk_ID1 = x * c_ID1 + b1 mod q
 *   where c_ID1 = H1(ID_1 || Q_ID1)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "RequiredFunctions.h"

static char ID_1[1024];

int main(int argc, char **argv) {
    EC_GROUP *group = NULL;
    BIGNUM *q = NULL;
    const EC_POINT *P = NULL;

    BIGNUM *x = NULL;        /* sk_ID0 (master secret scalar) */
    BIGNUM *b1 = NULL;       /* random delegation scalar */
    EC_POINT *Q_ID1 = NULL;  /* public delegation point */
    BIGNUM *c_ID1 = NULL;    /* hash-derived scalar */
    BIGNUM *sk_ID1 = NULL;   /* derived private key */

    BN_CTX *ctx = NULL;

    unsigned char *qid1_bytes = NULL;
    unsigned char *buf = NULL;
    BIGNUM *tmp = NULL;

    size_t id_len = 0;
    const char *id_path = NULL;
    const char *b1_path = NULL;
    const char *msk_path = NULL;

    if (argc != 4) {
        fprintf(stderr, "Usage: %s <ID1.txt> <signer1_b1.txt> <msk.txt>\n", argv[0]);
        return EXIT_FAILURE;
    }

    id_path  = argv[1];
    b1_path  = argv[2];
    msk_path = argv[3];

    /* ------------------------------------------------------------ */
    /* Step 0: Initialize EC group and domain parameters             */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Call init_group(&group, &q)
     *   - Retrieve generator P using EC_GROUP_get0_generator()
     */
    /* ------------------------------------------------------------ */

    /* ------------------------------------------------------------ */
    /* Step 1: Read master secret x (sk_ID0) from msk.txt            */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Use read_bn_hex(msk_path, &x)
     *   - x is a scalar in Z_q
     */
    /* ------------------------------------------------------------ */

    /* ------------------------------------------------------------ */
    /* Step 2: Read identity string ID_1 from ID1.txt                */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Open ID1.txt
     *   - Read the identity string into ID_1
     *   - Strip newline characters
     *   - Compute id_len
     */
    /* ------------------------------------------------------------ */

    /* ------------------------------------------------------------ */
    /* Step 3: Initialize BN context and allocate scalars            */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Create BN_CTX using BN_CTX_new()
     *   - Allocate b1 and sk_ID1 using BN_new()
     */
    /* ------------------------------------------------------------ */

    /* ------------------------------------------------------------ */
    /* Step 4: Read delegation randomness b1                         */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Read scalar b1 from signer1_b1.txt using read_bn_hex()
     *   - b1 must lie in Z_q
     */
    /* ------------------------------------------------------------ */

    /* ------------------------------------------------------------ */
    /* Step 5: Compute Q_ID1 = b1 * P                                 */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Allocate Q_ID1 using EC_POINT_new(group)
     *   - Compute Q_ID1 = b1 * P
     *   - Use EC_POINT_mul(group, Q_ID1, NULL, P, b1, ctx)
     */
    /* ------------------------------------------------------------ */

    /* ------------------------------------------------------------ */
    /* Step 6: Compute c_ID1 = H1(ID_1 || Q_ID1)                      */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Serialize Q_ID1 using point_to_bytes()
     *   - Concatenate ID_1 || serialized Q_ID1 into a buffer
     *   - Hash buffer using H1_to_scalar()
     *   - Output must be a scalar mod q stored in c_ID1
     */
    /* ------------------------------------------------------------ */

    /* ------------------------------------------------------------ */
    /* Step 7: Compute sk_ID1 = x * c_ID1 + b1 mod q                  */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Allocate temporary BIGNUM tmp
     *   - Compute tmp = x * c_ID1 mod q using BN_mod_mul()
     *   - Compute sk_ID1 = tmp + b1 mod q using BN_mod_add()
     */
    /* ------------------------------------------------------------ */

    /* ------------------------------------------------------------ */
    /* Step 8: Write output keys                                     */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Write sk_ID1 to sk_ID1.txt using write_bn_hex()
     *   - Write Q_ID1 to Q_ID1.txt using write_point_hex()
     */
    /* ------------------------------------------------------------ */

    printf("[signer1] Delegation complete.\n");

    /* ------------------------------------------------------------ */
    /* Cleanup                                                       */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Free all allocated BIGNUMs, EC_POINTs, buffers, and contexts
     *   - Follow the same order as allocation
     */
    /* ------------------------------------------------------------ */

    return EXIT_SUCCESS;
}
