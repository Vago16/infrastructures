/*
 * verifier.c — Public Verifier for 2-Level Schnorr-HIBS
 *
 * ASSIGNMENT TEMPLATE
 *
 * ROLE:
 *   Implements HIBS.Verify for k = 2.
 *   Verifies a Schnorr-HIBS signature using only public information.
 *
 * INPUT FILES:
 *   - ID1.txt        : identity string for level 1
 *   - ID2.txt        : identity string for level 2
 *   - message.txt    : signed message
 *   - mpk.txt        : master public key
 *   - Q_ID1.txt      : level-1 public delegation point
 *   - Q_ID2.txt      : level-2 public delegation point
 *   - sig_s.txt      : signature scalar s
 *   - sig_h.txt      : signature hash h
 *
 * OUTPUT:
 *   - verification.txt : recomputed hash value (for debugging)
 *   - Console message indicating VALID or INVALID signature
 *
 * VERIFICATION EQUATION:
 *
 *   PK_eff =
 *     (c_ID1 * c_ID2) * mpk
 *     + (c_ID2 * Q_ID1)
 *     + Q_ID2
 *
 *   R' = s * P − h * PK_eff
 *
 *   Accept iff:
 *     h == H2(message || R')
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/bn.h>

#include "RequiredFunctions.h"

static char ID_1[1024];
static char ID_2[1024];
static char MESSAGE[4096];

int main(int argc, char **argv)
{
    EC_GROUP *group = NULL;
    BIGNUM *q = NULL;
    const EC_POINT *P = NULL;

    EC_POINT *mpk = NULL;
    EC_POINT *Q_ID1 = NULL;
    EC_POINT *Q_ID2 = NULL;

    BIGNUM *s = NULL;
    BIGNUM *h = NULL;

    BIGNUM *c_ID1 = NULL;
    BIGNUM *c_ID2 = NULL;
    BIGNUM *c1c2 = NULL;

    EC_POINT *PK_eff = NULL;
    EC_POINT *term1 = NULL;
    EC_POINT *term2 = NULL;

    EC_POINT *Rprime = NULL;
    EC_POINT *hpke = NULL;

    BIGNUM *h_check = NULL;

    BN_CTX *ctx = NULL;

    unsigned char *qid1_bytes = NULL;
    unsigned char *qid2_bytes = NULL;
    unsigned char *buf1 = NULL;
    unsigned char *buf2 = NULL;
    unsigned char *Rprime_bytes = NULL;
    unsigned char *hbuf = NULL;

    size_t id1_len = 0;
    size_t id2_len = 0;
    size_t m_len = 0;

    const char *id1_path = NULL;
    const char *id2_path = NULL;
    const char *msg_path = NULL;
    const char *mpk_path = NULL;
    const char *qid1_path = NULL;
    const char *qid2_path = NULL;
    const char *sig_s_path = NULL;
    const char *sig_h_path = NULL;

    if (argc != 9)
    {
        fprintf(stderr,
            "Usage: %s <ID1.txt> <ID2.txt> <message.txt> <mpk.txt> "
            "<Q_ID1.txt> <Q_ID2.txt> <sig_s.txt> <sig_h.txt>\n",
            argv[0]);
        return EXIT_FAILURE;
    }

    id1_path   = argv[1];
    id2_path   = argv[2];
    msg_path   = argv[3];
    mpk_path   = argv[4];
    qid1_path  = argv[5];
    qid2_path  = argv[6];
    sig_s_path = argv[7];
    sig_h_path = argv[8];

    /* ------------------------------------------------------------ */
    /* Step 0: Initialize elliptic curve parameters                  */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Call init_group(&group, &q)
     *   - Retrieve generator P using EC_GROUP_get0_generator()
     */
    /* ------------------------------------------------------------ */

    /* ------------------------------------------------------------ */
    /* Step 1: Read public parameters and signature                  */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Read mpk from mpk.txt using read_point_hex()
     *   - Read Q_ID1 and Q_ID2 using read_point_hex()
     *   - Read signature scalars s and h using read_bn_hex()
     */
    /* ------------------------------------------------------------ */

    /* ------------------------------------------------------------ */
    /* Step 2: Read identities and message                            */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Read ID_1 from ID1.txt and compute id1_len
     *   - Read ID_2 from ID2.txt and compute id2_len
     *   - Read MESSAGE from message.txt and compute m_len
     */
    /* ------------------------------------------------------------ */

    /* ------------------------------------------------------------ */
    /* Step 3: Initialize BN context                                  */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Create BN_CTX using BN_CTX_new()
     */
    /* ------------------------------------------------------------ */

    /* ------------------------------------------------------------ */
    /* Step 4: Compute c_ID1 = H1(ID_1 || Q_ID1)                      */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Serialize Q_ID1 using point_to_bytes()
     *   - Concatenate ID_1 || Q_ID1
     *   - Hash using H1_to_scalar() to obtain c_ID1
     */
    /* ------------------------------------------------------------ */

    /* ------------------------------------------------------------ */
    /* Step 5: Compute c_ID2 = H1(ID_2 || Q_ID1 || Q_ID2)             */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Serialize Q_ID1 and Q_ID2 using point_to_bytes()
     *   - Concatenate ID_2 || Q_ID1 || Q_ID2
     *   - Hash using H1_to_scalar() to obtain c_ID2
     */
    /* ------------------------------------------------------------ */

    /* ------------------------------------------------------------ */
    /* Step 6: Reconstruct effective public key PK_eff                */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Compute c1c2 = c_ID1 * c_ID2 mod q using BN_mod_mul()
     *   - Compute term1 = (c1c2) * mpk using EC_POINT_mul()
     *   - Compute term2 = c_ID2 * Q_ID1 using EC_POINT_mul()
     *   - Compute PK_eff = term1 + term2 + Q_ID2 using EC_POINT_add()
     */
    /* ------------------------------------------------------------ */

    /* ------------------------------------------------------------ */
    /* Step 7: Compute R' = s * P − h * PK_eff                         */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Compute hpke = h * PK_eff using EC_POINT_mul()
     *   - Invert hpke using EC_POINT_invert()
     *   - Compute s * P using EC_POINT_mul()
     *   - Add points to obtain R' using EC_POINT_add()
     */
    /* ------------------------------------------------------------ */

    /* ------------------------------------------------------------ */
    /* Step 8: Verify hash consistency                                */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Serialize R' using point_to_bytes()
     *   - Concatenate MESSAGE || R'
     *   - Hash using H2_to_scalar() to obtain h_check
     *   - Compare h_check and h using BN_cmp()
     *   - Write h_check to verification.txt using write_bn_hex()
     */
    /* ------------------------------------------------------------ */

    /* ------------------------------------------------------------ */
    /* Step 9: Output verification result                             */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Print VALID if h == h_check
     *   - Print INVALID otherwise
     */
    /* ------------------------------------------------------------ */

    printf("[verifier] Verification completed.\n");

    /* ------------------------------------------------------------ */
    /* Cleanup                                                       */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Free all allocated BIGNUMs, EC_POINTs, buffers, and contexts
     *   - Ensure no memory leaks
     */
    /* ------------------------------------------------------------ */

    return EXIT_SUCCESS;
}
