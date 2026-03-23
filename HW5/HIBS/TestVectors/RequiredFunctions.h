#ifndef REQUIREDFUNCTIONS_H
#define REQUIREDFUNCTIONS_H

#include <stddef.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

/* Initialize standard EC group and extract its order q.
 * - Currently uses NID_X9_62_prime256v1 (secp256r1).
 * Returns 1 on success, 0 on error.
 */
int init_group(EC_GROUP **group, BIGNUM **order);

/* H1: hash arbitrary data to scalar mod q. Returns 1 on success. */
int H1_to_scalar(const unsigned char *data, size_t data_len,
                 const BIGNUM *q, BIGNUM **out);

/* H2: hash arbitrary data to scalar mod q. Returns 1 on success. */
int H2_to_scalar(const unsigned char *data, size_t data_len,
                 const BIGNUM *q, BIGNUM **out);

/* Hex file I/O for BIGNUM scalars. Return 1 on success. */
int write_bn_hex(const char *filename, const BIGNUM *bn);
int read_bn_hex(const char *filename, BIGNUM **bn);

/* Hex file I/O for EC points in uncompressed form. Return 1 on success. */
int write_point_hex(const char *filename, const EC_GROUP *group,
                    const EC_POINT *point);
int read_point_hex(const char *filename, const EC_GROUP *group,
                   EC_POINT **point);

/* Serialize EC point to bytes (uncompressed). Caller must free *out. */
int point_to_bytes(const EC_GROUP *group, const EC_POINT *point,
                   unsigned char **out, size_t *out_len);

#endif /* REQUIREDFUNCTIONS_H */
