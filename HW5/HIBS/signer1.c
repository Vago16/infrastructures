#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/bn.h>

#include "RequiredFunctions.h"

static char ID_1[1024];

int main(int argc, char **argv) {
    EC_GROUP *group = NULL;
    BIGNUM *q = NULL;
    const EC_POINT *P = NULL;

    BIGNUM *x = NULL;
    BIGNUM *b1 = NULL;
    EC_POINT *Q_ID1 = NULL;
    BIGNUM *c_ID1 = NULL;
    BIGNUM *sk_ID1 = NULL;

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

    if (!init_group(&group, &q)) {
        fprintf(stderr, "init_group failed\n");
        return EXIT_FAILURE;
    }

    P = EC_GROUP_get0_generator(group);
    if (P == NULL) {
        fprintf(stderr, "failed getting generator\n");
        return EXIT_FAILURE;
    }

    if (!read_bn_hex(msk_path, &x)) {
        fprintf(stderr, "failed reading msk\n");
        return EXIT_FAILURE;
    }

    FILE *f = fopen(id_path, "r");
    if (!f) {
        fprintf(stderr, "failed opening ID1 file\n");
        return EXIT_FAILURE;
    }

    if (!fgets(ID_1, sizeof(ID_1), f)) {
        fclose(f);
        fprintf(stderr, "failed reading ID1\n");
        return EXIT_FAILURE;
    }
    fclose(f);

    ID_1[strcspn(ID_1, "\r\n")] = 0;
    id_len = strlen(ID_1);

    ctx = BN_CTX_new();
    b1 = BN_new();
    sk_ID1 = BN_new();
    tmp = BN_new();

    if (!ctx || !b1 || !sk_ID1 || !tmp) {
        fprintf(stderr, "allocation failed\n");
        return EXIT_FAILURE;
    }

    if (!read_bn_hex(b1_path, &b1)) {
        fprintf(stderr, "failed reading b1\n");
        return EXIT_FAILURE;
    }

    Q_ID1 = EC_POINT_new(group);
    if (!Q_ID1) {
        fprintf(stderr, "failed allocating Q_ID1\n");
        return EXIT_FAILURE;
    }

    if (!EC_POINT_mul(group, Q_ID1, NULL, P, b1, ctx)) {
        fprintf(stderr, "EC_POINT_mul failed\n");
        return EXIT_FAILURE;
    }

    size_t qid1_len = EC_POINT_point2oct(
        group, Q_ID1, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx
    );
    if (qid1_len == 0) {
        fprintf(stderr, "failed serializing Q_ID1 length\n");
        return EXIT_FAILURE;
    }

    qid1_bytes = malloc(qid1_len);
    if (!qid1_bytes) {
        fprintf(stderr, "malloc failed for qid1_bytes\n");
        return EXIT_FAILURE;
    }

    if (!EC_POINT_point2oct(
            group, Q_ID1, POINT_CONVERSION_UNCOMPRESSED,
            qid1_bytes, qid1_len, ctx)) {
        fprintf(stderr, "failed serializing Q_ID1\n");
        return EXIT_FAILURE;
    }

    buf = malloc(id_len + qid1_len);
    if (!buf) {
        fprintf(stderr, "malloc failed for buffer\n");
        return EXIT_FAILURE;
    }

    memcpy(buf, ID_1, id_len);
    memcpy(buf + id_len, qid1_bytes, qid1_len);

    if (!H1_to_scalar(buf, id_len + qid1_len, q, &c_ID1)) {
        fprintf(stderr, "H1 failed\n");
        return EXIT_FAILURE;
    }

    if (!BN_mod_mul(tmp, x, c_ID1, q, ctx)) {
        fprintf(stderr, "BN_mod_mul failed\n");
        return EXIT_FAILURE;
    }

    if (!BN_mod_add(sk_ID1, tmp, b1, q, ctx)) {
        fprintf(stderr, "BN_mod_add failed\n");
        return EXIT_FAILURE;
    }

    if (!write_bn_hex("sk_ID1.txt", sk_ID1)) {
        fprintf(stderr, "failed writing sk_ID1.txt\n");
        return EXIT_FAILURE;
    }

    if (!write_point_hex("Q_ID1.txt", group, Q_ID1)) {
        fprintf(stderr, "failed writing Q_ID1.txt\n");
        return EXIT_FAILURE;
    }

    printf("[signer1] Delegation complete.\n");

    BN_free(x);
    BN_free(b1);
    BN_free(c_ID1);
    BN_free(sk_ID1);
    BN_free(tmp);
    BN_CTX_free(ctx);
    EC_POINT_free(Q_ID1);
    EC_GROUP_free(group);
    BN_free(q);
    free(qid1_bytes);
    free(buf);

    return EXIT_SUCCESS;
}