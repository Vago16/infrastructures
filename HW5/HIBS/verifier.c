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

    size_t id1_len = 0, id2_len = 0, m_len = 0;

    if (argc != 9)
    {
        fprintf(stderr, "Usage error\n");
        return EXIT_FAILURE;
    }

    /* Step 0 */
    init_group(&group, &q);
    P = EC_GROUP_get0_generator(group);

    /* Step 1 */
    read_point_hex(argv[4], group, &mpk);
    read_point_hex(argv[5], group, &Q_ID1);
    read_point_hex(argv[6], group, &Q_ID2);
    read_bn_hex(argv[7], &s);
    read_bn_hex(argv[8], &h);

    /* Step 2 */
    FILE *f = fopen(argv[1], "r");
    fgets(ID_1, sizeof(ID_1), f); fclose(f);
    ID_1[strcspn(ID_1,"\r\n")] = 0;
    id1_len = strlen(ID_1);

    f = fopen(argv[2], "r");
    fgets(ID_2, sizeof(ID_2), f); fclose(f);
    ID_2[strcspn(ID_2,"\r\n")] = 0;
    id2_len = strlen(ID_2);

    f = fopen(argv[3], "r");
    fgets(MESSAGE, sizeof(MESSAGE), f); fclose(f);
    MESSAGE[strcspn(MESSAGE,"\r\n")] = 0;
    m_len = strlen(MESSAGE);

    /* Step 3 */
    ctx = BN_CTX_new();

    /* Step 4: c_ID1 */
    size_t q1_len = EC_POINT_point2oct(group, Q_ID1, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
    qid1_bytes = malloc(q1_len);
    EC_POINT_point2oct(group, Q_ID1, POINT_CONVERSION_UNCOMPRESSED, qid1_bytes, q1_len, ctx);

    buf1 = malloc(id1_len + q1_len);
    memcpy(buf1, ID_1, id1_len);
    memcpy(buf1 + id1_len, qid1_bytes, q1_len);

    H1_to_scalar(buf1, id1_len + q1_len, q, &c_ID1);

    /* Step 5: c_ID2 */
    size_t q2_len = EC_POINT_point2oct(group, Q_ID2, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
    qid2_bytes = malloc(q2_len);
    EC_POINT_point2oct(group, Q_ID2, POINT_CONVERSION_UNCOMPRESSED, qid2_bytes, q2_len, ctx);

    buf2 = malloc(id2_len + q1_len + q2_len);
    memcpy(buf2, ID_2, id2_len);
    memcpy(buf2 + id2_len, qid1_bytes, q1_len);
    memcpy(buf2 + id2_len + q1_len, qid2_bytes, q2_len);

    H1_to_scalar(buf2, id2_len + q1_len + q2_len, q, &c_ID2);

    /* Step 6: PK_eff */
    c1c2 = BN_new();
    BN_mod_mul(c1c2, c_ID1, c_ID2, q, ctx);

    term1 = EC_POINT_new(group);
    term2 = EC_POINT_new(group);
    PK_eff = EC_POINT_new(group);

    EC_POINT_mul(group, term1, NULL, mpk, c1c2, ctx);
    EC_POINT_mul(group, term2, NULL, Q_ID1, c_ID2, ctx);

    EC_POINT_copy(PK_eff, term1);
    EC_POINT_add(group, PK_eff, PK_eff, term2, ctx);
    EC_POINT_add(group, PK_eff, PK_eff, Q_ID2, ctx);

    /* Step 7: R' */
    hpke = EC_POINT_new(group);
    EC_POINT_mul(group, hpke, NULL, PK_eff, h, ctx);
    EC_POINT_invert(group, hpke, ctx);

    Rprime = EC_POINT_new(group);
    EC_POINT_mul(group, Rprime, NULL, P, s, ctx);
    EC_POINT_add(group, Rprime, Rprime, hpke, ctx);

    /* Step 8: h_check */
    size_t R_len = EC_POINT_point2oct(group, Rprime, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
    Rprime_bytes = malloc(R_len);
    EC_POINT_point2oct(group, Rprime, POINT_CONVERSION_UNCOMPRESSED, Rprime_bytes, R_len, ctx);

    hbuf = malloc(m_len + R_len);
    memcpy(hbuf, MESSAGE, m_len);
    memcpy(hbuf + m_len, Rprime_bytes, R_len);

    H2_to_scalar(hbuf, m_len + R_len, q, &h_check);

    write_bn_hex("verification.txt", h_check);

    /* Step 9 */
    if (BN_cmp(h, h_check) == 0)
        printf("[verifier] VALID signature\n");
    else
        printf("[verifier] INVALID signature\n");

    return 0;
}