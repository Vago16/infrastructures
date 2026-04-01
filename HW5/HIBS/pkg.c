#include <stdio.h>
#include <stdlib.h>

#include <openssl/ec.h>
#include <openssl/bn.h>

#include "RequiredFunctions.h"

int main(int argc, char **argv)
{
    int ret = EXIT_FAILURE;

    EC_GROUP *group = NULL;
    BIGNUM *q = NULL;
    const EC_POINT *P = NULL;

    BIGNUM *msk = NULL;
    EC_POINT *mpk = NULL;

    BN_CTX *ctx = NULL;

    if (!init_group(&group, &q))
    {
        fprintf(stderr, "[PKG] Error: init_group failed.\n");
        goto cleanup;
    }

    P = EC_GROUP_get0_generator(group);
    if (P == NULL)
    {
        fprintf(stderr, "[PKG] Error: could not get generator.\n");
        goto cleanup;
    }

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <pkg_x.txt>\n", argv[0]);
        goto cleanup;
    }

    ctx = BN_CTX_new();
    if (ctx == NULL)
    {
        fprintf(stderr, "[PKG] Error: BN_CTX_new failed.\n");
        goto cleanup;
    }

    if (!read_bn_hex(argv[1], &msk))
    {
        fprintf(stderr, "[PKG] Error: failed to read master secret from %s\n", argv[1]);
        goto cleanup;
    }

    mpk = EC_POINT_new(group);
    if (mpk == NULL)
    {
        fprintf(stderr, "[PKG] Error: EC_POINT_new failed.\n");
        goto cleanup;
    }

    if (!EC_POINT_mul(group, mpk, NULL, P, msk, ctx))
    {
        fprintf(stderr, "[PKG] Error: EC_POINT_mul failed.\n");
        goto cleanup;
    }

    if (!write_point_hex("mpk.txt", group, mpk))
    {
        fprintf(stderr, "[PKG] Error: failed to write mpk.txt\n");
        goto cleanup;
    }

    printf("[PKG] Setup complete. Wrote mpk.txt.\n");
    ret = EXIT_SUCCESS;

cleanup:
    EC_POINT_free(mpk);
    BN_free(msk);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);
    BN_free(q);

    return ret;
}