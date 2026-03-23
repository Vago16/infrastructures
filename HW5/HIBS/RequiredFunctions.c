// Common utility functions for the 2-level Schnorr-HIBS demo.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "RequiredFunctions.h"

static void print_openssl_error(const char *where) {
	fprintf(stderr, "%s failed: %s\n", where, ERR_error_string(ERR_get_error(), NULL));
}

int init_group(EC_GROUP **group, BIGNUM **order) {
	if (!group || !order) return 0;

	*group = NULL;
	*order = NULL;

	EC_GROUP *g = EC_GROUP_new_by_curve_name(NID_secp256k1); // secp256k1
	if (!g) {
		print_openssl_error("EC_GROUP_new_by_curve_name");
		return 0;
	}

	EC_GROUP_set_point_conversion_form(g, POINT_CONVERSION_UNCOMPRESSED);

	BIGNUM *q = BN_new();
	if (!q) {
		EC_GROUP_free(g);
		return 0;
	}

	if (!EC_GROUP_get_order(g, q, NULL)) {
		print_openssl_error("EC_GROUP_get_order");
		BN_free(q);
		EC_GROUP_free(g);
		return 0;
	}

	*group = g;
	*order = q;
	return 1;
}

static int hash_to_scalar_internal(unsigned char prefix,
								   const unsigned char *data, size_t data_len,
								   const BIGNUM *q, BIGNUM **out) {
	if (!data || !q || !out) return 0;

	SHA256_CTX ctx;
	unsigned char digest[SHA256_DIGEST_LENGTH];

	if (!SHA256_Init(&ctx)) return 0;
	if (!SHA256_Update(&ctx, &prefix, 1)) return 0;
	if (data_len > 0 && !SHA256_Update(&ctx, data, data_len)) return 0;
	if (!SHA256_Final(digest, &ctx)) return 0;

	BIGNUM *tmp = BN_bin2bn(digest, SHA256_DIGEST_LENGTH, NULL);
	if (!tmp) return 0;

	BN_CTX *bn_ctx = BN_CTX_new();
	if (!bn_ctx) {
		BN_free(tmp);
		return 0;
	}

	BIGNUM *res = BN_new();
	if (!res) {
		BN_free(tmp);
		BN_CTX_free(bn_ctx);
		return 0;
	}

	if (!BN_mod(res, tmp, q, bn_ctx)) {
		print_openssl_error("BN_mod");
		BN_free(tmp);
		BN_free(res);
		BN_CTX_free(bn_ctx);
		return 0;
	}

	// Ensure non-zero scalar (very unlikely to be zero in practice)
	if (BN_is_zero(res)) {
		if (!BN_one(res)) {
			BN_free(tmp);
			BN_free(res);
			BN_CTX_free(bn_ctx);
			return 0;
		}
	}

	BN_free(tmp);
	BN_CTX_free(bn_ctx);
	*out = res;
	return 1;
}

int H1_to_scalar(const unsigned char *data, size_t data_len,
				 const BIGNUM *q, BIGNUM **out) {
	return hash_to_scalar_internal(0x01, data, data_len, q, out);
}

int H2_to_scalar(const unsigned char *data, size_t data_len,
				 const BIGNUM *q, BIGNUM **out) {
	return hash_to_scalar_internal(0x02, data, data_len, q, out);
}

int write_bn_hex(const char *filename, const BIGNUM *bn) {
	if (!filename || !bn) return 0;

	char *hex = BN_bn2hex(bn);
	if (!hex) return 0;

	FILE *f = fopen(filename, "w");
	if (!f) {
		OPENSSL_free(hex);
		return 0;
	}

	fprintf(f, "%s\n", hex);
	fclose(f);
	OPENSSL_free(hex);
	return 1;
}

int read_bn_hex(const char *filename, BIGNUM **bn) {
	if (!filename || !bn) return 0;

	FILE *f = fopen(filename, "r");
	if (!f) return 0;

	char buf[4096];
	if (!fgets(buf, sizeof(buf), f)) {
		fclose(f);
		return 0;
	}
	fclose(f);

	// Strip newline
	size_t len = strlen(buf);
	if (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
		buf[len - 1] = '\0';
	}

	BIGNUM *res = NULL;
	if (!BN_hex2bn(&res, buf)) {
		return 0;
	}

	*bn = res;
	return 1;
}

static int hexchar_to_nibble(char c, unsigned char *out) {
	if (c >= '0' && c <= '9') {
		*out = (unsigned char)(c - '0');
		return 1;
	}
	if (c >= 'a' && c <= 'f') {
		*out = (unsigned char)(10 + (c - 'a'));
		return 1;
	}
	if (c >= 'A' && c <= 'F') {
		*out = (unsigned char)(10 + (c - 'A'));
		return 1;
	}
	return 0;
}

int point_to_bytes(const EC_GROUP *group, const EC_POINT *point,
				   unsigned char **out, size_t *out_len) {
	if (!group || !point || !out || !out_len) return 0;

	BN_CTX *ctx = BN_CTX_new();
	if (!ctx) return 0;

	size_t len = EC_POINT_point2oct(group, point,
									POINT_CONVERSION_UNCOMPRESSED,
									NULL, 0, ctx);
	if (len == 0) {
		print_openssl_error("EC_POINT_point2oct(size)");
		BN_CTX_free(ctx);
		return 0;
	}

	unsigned char *buf = (unsigned char *)malloc(len);
	if (!buf) {
		BN_CTX_free(ctx);
		return 0;
	}

	if (!EC_POINT_point2oct(group, point,
							 POINT_CONVERSION_UNCOMPRESSED,
							 buf, len, ctx)) {
		print_openssl_error("EC_POINT_point2oct(data)");
		free(buf);
		BN_CTX_free(ctx);
		return 0;
	}

	BN_CTX_free(ctx);
	*out = buf;
	*out_len = len;
	return 1;
}

int write_point_hex(const char *filename, const EC_GROUP *group,
					const EC_POINT *point) {
	if (!filename || !group || !point) return 0;

	unsigned char *buf = NULL;
	size_t len = 0;
	if (!point_to_bytes(group, point, &buf, &len)) return 0;

	FILE *f = fopen(filename, "w");
	if (!f) {
		free(buf);
		return 0;
	}

	for (size_t i = 0; i < len; i++) {
		fprintf(f, "%02X", buf[i]);
	}
	fprintf(f, "\n");
	fclose(f);
	free(buf);
	return 1;
}

int read_point_hex(const char *filename, const EC_GROUP *group,
				   EC_POINT **point) {
	if (!filename || !group || !point) return 0;

	FILE *f = fopen(filename, "r");
	if (!f) return 0;

	char *line = NULL;
	size_t cap = 0;
	ssize_t read = getline(&line, &cap, f);
	fclose(f);
	if (read <= 0) {
		free(line);
		return 0;
	}

	// Strip newline
	if (line[read - 1] == '\n' || line[read - 1] == '\r') {
		line[read - 1] = '\0';
		read--;
	}

	size_t hex_len = (size_t)read;
	if (hex_len % 2 != 0) {
		free(line);
		return 0;
	}

	size_t byte_len = hex_len / 2;
	unsigned char *buf = (unsigned char *)malloc(byte_len);
	if (!buf) {
		free(line);
		return 0;
	}

	for (size_t i = 0; i < byte_len; i++) {
		unsigned char hi, lo;
		if (!hexchar_to_nibble(line[2 * i], &hi) ||
			!hexchar_to_nibble(line[2 * i + 1], &lo)) {
			free(buf);
			free(line);
			return 0;
		}
		buf[i] = (unsigned char)((hi << 4) | lo);
	}

	free(line);

	EC_POINT *pt = EC_POINT_new(group);
	if (!pt) {
		free(buf);
		return 0;
	}

	BN_CTX *ctx = BN_CTX_new();
	if (!ctx) {
		free(buf);
		EC_POINT_free(pt);
		return 0;
	}

	if (!EC_POINT_oct2point(group, pt, buf, byte_len, ctx)) {
		print_openssl_error("EC_POINT_oct2point");
		free(buf);
		EC_POINT_free(pt);
		BN_CTX_free(ctx);
		return 0;
	}

	free(buf);
	BN_CTX_free(ctx);
	*point = pt;
	return 1;
}
