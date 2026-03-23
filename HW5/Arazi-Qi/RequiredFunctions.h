#ifndef REQUIREDFUNCTIONS_H
#define REQUIREDFUNCTIONS_H

#include <stddef.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

/* Initialize EC group on secp256k1 and return group and its order q. */
int init_group(EC_GROUP **group, BIGNUM **order);

/* Hash arbitrary data with SHA-256 and reduce mod q to get a scalar. */
int sha256_to_scalar(const unsigned char *data, size_t data_len,
                     const BIGNUM *q, BIGNUM **out);

/* Hex file I/O for BIGNUM scalars. */
int write_bn_hex(const char *filename, const BIGNUM *bn);
int read_bn_hex(const char *filename, BIGNUM **bn);

/* Serialize EC point to uncompressed octets; caller frees *out. */
int point_to_bytes(const EC_GROUP *group, const EC_POINT *point,
                   unsigned char **out, size_t *out_len);

/* Hex file I/O for EC points (uncompressed form encoded as hex). */
int write_point_hex(const char *filename, const EC_GROUP *group,
                    const EC_POINT *point);
int read_point_hex(const char *filename, const EC_GROUP *group,
                   EC_POINT **point);

#endif /* REQUIREDFUNCTIONS_H */
