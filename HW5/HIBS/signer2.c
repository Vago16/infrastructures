#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/bn.h>

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

    if (argc != 7)
    {
        fprintf(stderr, "Usage: %s <sk_ID1> <b2> <r> <Q_ID1> <ID2> <msg>\n", argv[0]);
        return EXIT_FAILURE;
    }

    /* Step 0 */
    if (!init_group(&group, &q)) return EXIT_FAILURE;
    P = EC_GROUP_get0_generator(group);

    /* Step 1 */
    read_bn_hex(argv[1], &sk_ID1);
    read_point_hex(argv[4], group, &Q_ID1);

    /* Step 2 */
    FILE *f = fopen(argv[5], "r");
    fgets(ID_2, sizeof(ID_2), f);
    fclose(f);
    ID_2[strcspn(ID_2, "\r\n")] = 0;
    id_len = strlen(ID_2);

    f = fopen(argv[6], "r");
    fgets(MESSAGE, sizeof(MESSAGE), f);
    fclose(f);
    MESSAGE[strcspn(MESSAGE, "\r\n")] = 0;
    m_len = strlen(MESSAGE);

    /* Step 3 */
    ctx = BN_CTX_new();
    b2 = BN_new();
    sk_ID2 = BN_new();
    r = BN_new();
    s = BN_new();

    /* Step 4 */
    read_bn_hex(argv[2], &b2);
    Q_ID2 = EC_POINT_new(group);
    EC_POINT_mul(group, Q_ID2, NULL, P, b2, ctx);

    /* Step 5 */
    size_t q1_len = EC_POINT_point2oct(group, Q_ID1, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
    size_t q2_len = EC_POINT_point2oct(group, Q_ID2, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);

    qid1_bytes = malloc(q1_len);
    qid2_bytes = malloc(q2_len);

    EC_POINT_point2oct(group, Q_ID1, POINT_CONVERSION_UNCOMPRESSED, qid1_bytes, q1_len, ctx);
    EC_POINT_point2oct(group, Q_ID2, POINT_CONVERSION_UNCOMPRESSED, qid2_bytes, q2_len, ctx);

    buf = malloc(id_len + q1_len + q2_len);
    memcpy(buf, ID_2, id_len);
    memcpy(buf + id_len, qid1_bytes, q1_len);
    memcpy(buf + id_len + q1_len, qid2_bytes, q2_len);

    H1_to_scalar(buf, id_len + q1_len + q2_len, q, &c_ID2);

    /* Step 6 */
    tmp = BN_new();
    BN_mod_mul(tmp, sk_ID1, c_ID2, q, ctx);
    BN_mod_add(sk_ID2, tmp, b2, q, ctx);

    /* Step 7 */
    read_bn_hex(argv[3], &r);
    R = EC_POINT_new(group);
    EC_POINT_mul(group, R, NULL, P, r, ctx);

    /* Step 8 */
    size_t R_len = EC_POINT_point2oct(group, R, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
    R_bytes = malloc(R_len);

    EC_POINT_point2oct(group, R, POINT_CONVERSION_UNCOMPRESSED, R_bytes, R_len, ctx);

    hbuf = malloc(m_len + R_len);
    memcpy(hbuf, MESSAGE, m_len);
    memcpy(hbuf + m_len, R_bytes, R_len);

    H2_to_scalar(hbuf, m_len + R_len, q, &h);

    /* Step 9 */
    tmp2 = BN_new();
    BN_mod_mul(tmp2, h, sk_ID2, q, ctx);
    BN_mod_add(s, r, tmp2, q, ctx);

    /* Step 10 */
    write_point_hex("Q_ID2.txt", group, Q_ID2);
    write_bn_hex("sig_s.txt", s);
    write_bn_hex("sig_h.txt", h);

    printf("[signer2] Delegation and signing complete.\n");

    return EXIT_SUCCESS;
}