/*
 * signer2.c — Level 2 Signer (ID_2) for Schnorr-HIBS
 *
 * ASSIGNMENT TEMPLATE
 *
 * ROLE:
 *   Implements:
 *     (1) HIBS.Extract for hierarchy level k = 2
 *     (2) Schnorr signature generation
 *
 * INPUT FILES:
 *   - sk_ID1.txt          : level-1 private key (hex scalar)
 *   - signer2_b2.txt     : random delegation scalar b2 (hex)
 *   - signer2_r.txt      : signing randomness r (hex)
 *   - Q_ID1.txt          : level-1 public delegation point (hex EC point)
 *   - ID2.txt             : identity string for ID_2
 *   - message.txt         : message to be signed
 *
 * OUTPUT FILES:
 *   - Q_ID2.txt            : level-2 public delegation point
 *   - sig_s.txt            : Schnorr signature scalar s
 *   - sig_h.txt            : Schnorr signature hash h
 *
 * REQUIRED RELATIONS:
 *   Delegation:
 *     c_ID2 = H1(ID_2 || Q_ID1 || Q_ID2)
 *     sk_ID2 = sk_ID1 * c_ID2 + b2 mod q
 *
 *   Signing:
 *     R = r * P
 *     h = H2(message || R)
 *     s = r + h * sk_ID2 mod q
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "RequiredFunctions.h"

static char ID_2[1024];
static char MESSAGE[4096];

int main(int argc, char **argv)
{
    EC_GROUP *group = NULL;
    BIGNUM *q = NULL;
    const EC_POINT *P = NULL;

    BIGNUM *sk_ID1 = NULL;
    EC_POINT *Q_ID1 = NULL;

    BIGNUM *b2 = NULL;
    EC_POINT *Q_ID2 = NULL;
    BIGNUM *c_ID2 = NULL;
    BIGNUM *sk_ID2 = NULL;

    BIGNUM *r = NULL;
    EC_POINT *R = NULL;
    BIGNUM *h = NULL;
    BIGNUM *s = NULL;

    BN_CTX *ctx = NULL;

    unsigned char *qid1_bytes = NULL;
    unsigned char *qid2_bytes = NULL;
    unsigned char *buf = NULL;
    unsigned char *R_bytes = NULL;
    unsigned char *hbuf = NULL;

    BIGNUM *tmp = NULL;
    BIGNUM *tmp2 = NULL;

    size_t id_len = 0;
    size_t m_len = 0;

    const char *sk_id1_path = NULL;
    const char *b2_path = NULL;
    const char *r_path = NULL;
    const char *q_id1_path = NULL;
    const char *id2_path = NULL;
    const char *msg_path = NULL;

    if (argc != 7)
    {
        fprintf(stderr,
            "Usage: %s <sk_ID1.txt> <signer2_b2.txt> <signer2_r.txt> "
            "<Q_ID1.txt> <ID2.txt> <message.txt>\n", argv[0]);
        return EXIT_FAILURE;
    }

    sk_id1_path = argv[1];
    b2_path     = argv[2];
    r_path      = argv[3];
    q_id1_path  = argv[4];
    id2_path    = argv[5];
    msg_path    = argv[6];

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
    /* Step 1: Read level-1 secret key and public delegation point   */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Read sk_ID1 from sk_ID1.txt using read_bn_hex()
     *   - Read Q_ID1 from Q_ID1.txt using read_point_hex()
     */
    /* ------------------------------------------------------------ */

    /* ------------------------------------------------------------ */
    /* Step 2: Read identity ID_2 and message                        */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Open ID2.txt and read identity string into ID_2
     *   - Strip newline characters and compute id_len
     *
     *   - Open message.txt and read message into MESSAGE
     *   - Strip newline characters and compute m_len
     */
    /* ------------------------------------------------------------ */

    /* ------------------------------------------------------------ */
    /* Step 3: Initialize BN context and allocate scalars            */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Create BN_CTX using BN_CTX_new()
     *   - Allocate b2, sk_ID2, r, and s using BN_new()
     */
    /* ------------------------------------------------------------ */

    /* ------------------------------------------------------------ */
    /* Step 4: Delegation — read b2 and compute Q_ID2                */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Read b2 from signer2_b2.txt using read_bn_hex()
     *   - Allocate Q_ID2 using EC_POINT_new(group)
     *   - Compute Q_ID2 = b2 * P using EC_POINT_mul()
     */
    /* ------------------------------------------------------------ */

    /* ------------------------------------------------------------ */
    /* Step 5: Compute c_ID2 = H1(ID_2 || Q_ID1 || Q_ID2)             */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Serialize Q_ID1 and Q_ID2 using point_to_bytes()
     *   - Concatenate ID_2 || Q_ID1 || Q_ID2 into buffer
     *   - Hash buffer to scalar c_ID2 using H1_to_scalar()
     */
    /* ------------------------------------------------------------ */

    /* ------------------------------------------------------------ */
    /* Step 6: Compute sk_ID2 = sk_ID1 * c_ID2 + b2 mod q             */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Allocate temporary BIGNUM tmp
     *   - Compute tmp = sk_ID1 * c_ID2 mod q using BN_mod_mul()
     *   - Compute sk_ID2 = tmp + b2 mod q using BN_mod_add()
     */
    /* ------------------------------------------------------------ */

    /* ------------------------------------------------------------ */
    /* Step 7: Signing — read r and compute R                         */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Read r from signer2_r.txt using read_bn_hex()
     *   - Allocate EC_POINT R
     *   - Compute R = r * P using EC_POINT_mul()
     */
    /* ------------------------------------------------------------ */

    /* ------------------------------------------------------------ */
    /* Step 8: Compute h = H2(message || R)                           */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Serialize R using point_to_bytes()
     *   - Concatenate MESSAGE || R into buffer
     *   - Hash buffer to scalar h using H2_to_scalar()
     */
    /* ------------------------------------------------------------ */

    /* ------------------------------------------------------------ */
    /* Step 9: Compute s = r + h * sk_ID2 mod q                       */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Allocate temporary BIGNUM tmp2
     *   - Compute tmp2 = h * sk_ID2 mod q using BN_mod_mul()
     *   - Compute s = r + tmp2 mod q using BN_mod_add()
     */
    /* ------------------------------------------------------------ */

    /* ------------------------------------------------------------ */
    /* Step 10: Write output files                                   */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Write Q_ID2 to Q_ID2.txt using write_point_hex()
     *   - Write s to sig_s.txt using write_bn_hex()
     *   - Write h to sig_h.txt using write_bn_hex()
     */
    /* ------------------------------------------------------------ */

    printf("[signer2] Delegation and signing complete.\n");

    /* ------------------------------------------------------------ */
    /* Cleanup                                                       */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Free all allocated BIGNUMs, EC_POINTs, buffers, and contexts
     *   - Follow correct order and avoid memory leaks
     */
    /* ------------------------------------------------------------ */

    return EXIT_SUCCESS;
}
