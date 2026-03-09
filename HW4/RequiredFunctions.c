#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

static int file_exists(const char *path) {
	FILE *f = fopen(path, "r");
	if (!f)
		return 0;
	fclose(f);
	return 1;
}

static char *trim_newline(char *s) {
	if (!s)
		return NULL;
	size_t len = strlen(s);
	while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r')) {
		s[--len] = '\0';
	}
	return s;
}

static char *read_line(const char *path, int line_no) {
	FILE *f = fopen(path, "r");
	if (!f)
		return NULL;
	char *buf = NULL;
	size_t cap = 0;
	int current = 0;
	while (1) {
		if (cap == 0) {
			cap = 256;
			buf = malloc(cap);
			if (!buf)
				break;
		}
		if (!fgets(buf, (int)cap, f)) {
			free(buf);
			buf = NULL;
			break;
		}
		current++;
		if (current == line_no) {
			trim_newline(buf);
			break;
		}
	}
	fclose(f);
	return buf;
}

static int write_text_lines(const char *path, const char *l1, const char *l2, const char *l3) {
	FILE *f = fopen(path, "w");
	if (!f)
		return 0;
	if (l1)
		fprintf(f, "%s\n", l1);
	if (l2)
		fprintf(f, "%s\n", l2);
	if (l3)
		fprintf(f, "%s\n", l3);
	fclose(f);
	return 1;
}

static int hex_to_bytes(const char *hex, unsigned char **out, size_t *out_len) {
	if (!hex)
		return 0;
	size_t len = strlen(hex);
	if (len % 2 != 0)
		return 0;
	size_t blen = len / 2;
	unsigned char *buf = malloc(blen);
	if (!buf)
		return 0;
	for (size_t i = 0; i < blen; i++) {
		unsigned int v;
		if (sscanf(hex + 2 * i, "%2x", &v) != 1) {
			free(buf);
			return 0;
		}
		buf[i] = (unsigned char)v;
	}
	*out = buf;
	*out_len = blen;
	return 1;
}

static char *bytes_to_hex(const unsigned char *bytes, size_t len) {
	char *hex = malloc(len * 2 + 1);
	if (!hex)
		return NULL;
	for (size_t i = 0; i < len; i++) {
		sprintf(hex + 2 * i, "%02x", bytes[i]);
	}

	hex[len * 2] = '\0';
	return hex;
}

static int write_hex_file(const char *path, const unsigned char *data, size_t len) {
	char *hex = bytes_to_hex(data, len);
	if (!hex)
		return 0;
	FILE *f = fopen(path, "w");
	if (!f) {
		free(hex);
		return 0;
	}
	fprintf(f, "%s\n", hex);
	fclose(f);
	free(hex);
	return 1;
}

static int read_hex_file_bytes(const char *path, unsigned char **out, size_t *out_len) {
	char *line = read_line(path, 1);
	if (!line)
		return 0;
	int ok = hex_to_bytes(line, out, out_len);
	free(line);
	return ok;
}

static int sha256_bytes(const unsigned char *in, size_t in_len, unsigned char out[32]) {
	if (!SHA256(in, in_len, out))
		return 0;
	return 1;
}

static int random_sha256_bytes(unsigned char out[32]) {
	unsigned char rnd[32];
	if (RAND_bytes(rnd, sizeof(rnd)) != 1)
		return 0;
	return sha256_bytes(rnd, sizeof(rnd), out);
}

static int random_sha256_hex_file(const char *path, unsigned char out[32]) {
	unsigned char tmp[32];
	unsigned char *use = out ? out : tmp;
	if (!random_sha256_bytes(use))
		return 0;
	return write_hex_file(path, use, 32);
}

static EC_GROUP *create_group(void) {
	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	return group;
}

static int generate_ec_keypair_files(const char *sk_path, const char *pk_path) {
	int ret = 0;
	EC_KEY *ec_key = NULL;
	EC_GROUP *group = NULL;
	const BIGNUM *priv = NULL;
	const EC_POINT *pub = NULL;
	unsigned char *pub_buf = NULL;
	int pub_len;

	group = create_group();
	if (!group)
		goto cleanup;
	ec_key = EC_KEY_new();
	if (!ec_key)
		goto cleanup;
	if (EC_KEY_set_group(ec_key, group) != 1)
		goto cleanup;
	if (EC_KEY_generate_key(ec_key) != 1)
		goto cleanup;

	priv = EC_KEY_get0_private_key(ec_key);
	pub = EC_KEY_get0_public_key(ec_key);
	if (!priv || !pub)
		goto cleanup;

	int priv_len = BN_num_bytes(priv);
	unsigned char *priv_buf = malloc(priv_len);
	if (!priv_buf)
		goto cleanup;
	if (BN_bn2binpad(priv, priv_buf, priv_len) != priv_len) {
		free(priv_buf);
		goto cleanup;
	}
	if (!write_hex_file(sk_path, priv_buf, priv_len)) {
		free(priv_buf);
		goto cleanup;
	}
	free(priv_buf);

	pub_len = EC_POINT_point2buf(group, pub, POINT_CONVERSION_UNCOMPRESSED, &pub_buf, NULL);
	if (pub_len <= 0)
		goto cleanup;
	if (!write_hex_file(pk_path, pub_buf, (size_t)pub_len))
		goto cleanup;

	ret = 1;

cleanup:
	if (pub_buf)
		OPENSSL_free(pub_buf);
	if (ec_key)
		EC_KEY_free(ec_key);
	if (group)
		EC_GROUP_free(group);
	return ret;
}

static EC_KEY *load_private_key_hex_file(const char *sk_path) {
	unsigned char *priv_bytes = NULL;
	size_t priv_len = 0;
	if (!read_hex_file_bytes(sk_path, &priv_bytes, &priv_len))
		return NULL;
	EC_GROUP *group = create_group();
	if (!group) {
		free(priv_bytes);
		return NULL;
	}
	EC_KEY *ec_key = EC_KEY_new();
	if (!ec_key) {
		EC_GROUP_free(group);
		free(priv_bytes);
		return NULL;
	}
	if (EC_KEY_set_group(ec_key, group) != 1) {
		EC_KEY_free(ec_key);
		EC_GROUP_free(group);
		free(priv_bytes);
		return NULL;
	}
	BIGNUM *priv = BN_bin2bn(priv_bytes, (int)priv_len, NULL);
	free(priv_bytes);
	if (!priv) {
		EC_KEY_free(ec_key);
		EC_GROUP_free(group);
		return NULL;
	}
	if (EC_KEY_set_private_key(ec_key, priv) != 1) {
		BN_free(priv);
		EC_KEY_free(ec_key);
		EC_GROUP_free(group);
		return NULL;
	}
	BN_free(priv);
	EC_GROUP_free(group);
	return ec_key;
}

static EC_KEY *load_public_key_hex_file(const char *pk_path) {
	unsigned char *pub_bytes = NULL;
	size_t pub_len = 0;
	if (!read_hex_file_bytes(pk_path, &pub_bytes, &pub_len))
		return NULL;
	EC_GROUP *group = create_group();
	if (!group) {
		free(pub_bytes);
		return NULL;
	}
	EC_KEY *ec_key = EC_KEY_new();
	if (!ec_key) {
		EC_GROUP_free(group);
		free(pub_bytes);
		return NULL;
	}
	if (EC_KEY_set_group(ec_key, group) != 1) {
		EC_KEY_free(ec_key);
		EC_GROUP_free(group);
		free(pub_bytes);
		return NULL;
	}
	EC_POINT *pub = EC_POINT_new(group);
	if (!pub) {
		EC_KEY_free(ec_key);
		EC_GROUP_free(group);
		free(pub_bytes);
		return NULL;
	}
	if (EC_POINT_oct2point(group, pub, pub_bytes, pub_len, NULL) != 1) {
		EC_POINT_free(pub);
		EC_KEY_free(ec_key);
		EC_GROUP_free(group);
		free(pub_bytes);
		return NULL;
	}
	free(pub_bytes);
	if (EC_KEY_set_public_key(ec_key, pub) != 1) {
		EC_POINT_free(pub);
		EC_KEY_free(ec_key);
		EC_GROUP_free(group);
		return NULL;
	}
	EC_POINT_free(pub);
	EC_GROUP_free(group);
	return ec_key;
}

static int ecdh_shared_secret_files(const char *my_sk_path, const char *peer_pk_path, unsigned char **secret, size_t *secret_len) {
	int ret = 0;
	EC_KEY *my_key = load_private_key_hex_file(my_sk_path);
	EC_KEY *peer_key = load_public_key_hex_file(peer_pk_path);
	if (!my_key || !peer_key)
		goto cleanup;
	const EC_POINT *peer_pub = EC_KEY_get0_public_key(peer_key);
	if (!peer_pub)
		goto cleanup;
	const EC_GROUP *group = EC_KEY_get0_group(my_key);
	if (!group)
		goto cleanup;
	int field_size = EC_GROUP_get_degree(group);
	int out_len = (field_size + 7) / 8;
	unsigned char *buf = malloc(out_len);
	if (!buf)
		goto cleanup;
	int actual_len = ECDH_compute_key(buf, out_len, peer_pub, my_key, NULL);
	if (actual_len <= 0) {
		free(buf);
		goto cleanup;
	}
	*secret = buf;
	*secret_len = (size_t)actual_len;
	ret = 1;

cleanup:
	if (my_key)
		EC_KEY_free(my_key);
	if (peer_key)
		EC_KEY_free(peer_key);
	return ret;
}

static int aes256_ecb_encrypt(const unsigned char *key, const unsigned char *plaintext, int plaintext_len, unsigned char **ciphertext, int *ciphertext_len) {
	int ret = 0;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return 0;
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL) != 1)
		goto cleanup;
	EVP_CIPHER_CTX_set_padding(ctx, 1);
	int out_len1 = plaintext_len + EVP_CIPHER_block_size(EVP_aes_256_ecb());
	unsigned char *out = malloc(out_len1);
	if (!out)
		goto cleanup;
	int len = 0, total = 0;
	if (EVP_EncryptUpdate(ctx, out, &len, plaintext, plaintext_len) != 1) {
		free(out);
		goto cleanup;
	}
	total = len;
	if (EVP_EncryptFinal_ex(ctx, out + total, &len) != 1) {
		free(out);
		goto cleanup;
	}
	total += len;
	*ciphertext = out;
	*ciphertext_len = total;
	ret = 1;

cleanup:
	EVP_CIPHER_CTX_free(ctx);
	return ret;
}

static int aes256_ecb_decrypt(const unsigned char *key, const unsigned char *ciphertext, int ciphertext_len, unsigned char **plaintext, int *plaintext_len) {
	int ret = 0;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return 0;
	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL) != 1)
		goto cleanup;
	EVP_CIPHER_CTX_set_padding(ctx, 1);
	unsigned char *out = malloc(ciphertext_len + EVP_CIPHER_block_size(EVP_aes_256_ecb()));
	if (!out)
		goto cleanup;
	int len = 0, total = 0;
	if (EVP_DecryptUpdate(ctx, out, &len, ciphertext, ciphertext_len) != 1) {
		free(out);
		goto cleanup;
	}
	total = len;
	if (EVP_DecryptFinal_ex(ctx, out + total, &len) != 1) {
		free(out);
		goto cleanup;
	}
	total += len;
	*plaintext = out;
	*plaintext_len = total;
	ret = 1;

cleanup:
	EVP_CIPHER_CTX_free(ctx);
	return ret;
}

static int aes256_encrypt_bytes_to_hex_string(const unsigned char *key, const unsigned char *plaintext, size_t plaintext_len, char **hex_out) {
	unsigned char *cipher = NULL;
	int cipher_len = 0;
	if (!aes256_ecb_encrypt(key, plaintext, (int)plaintext_len, &cipher, &cipher_len))
		return 0;
	char *hex = bytes_to_hex(cipher, (size_t)cipher_len);
	free(cipher);
	if (!hex)
		return 0;
	*hex_out = hex;
	return 1;
}

static int aes256_decrypt_hex_string_to_bytes(const unsigned char *key, const char *hex_in, unsigned char **plaintext, size_t *plaintext_len) {
	unsigned char *cipher = NULL;
	size_t cipher_len = 0;
	if (!hex_to_bytes(hex_in, &cipher, &cipher_len))
		return 0;
	unsigned char *plain = NULL;
	int plain_len = 0;
	if (!aes256_ecb_decrypt(key, cipher, (int)cipher_len, &plain, &plain_len)) {
		free(cipher);
		return 0;
	}
	free(cipher);
	*plaintext = plain;
	*plaintext_len = (size_t)plain_len;
	return 1;
}

static int aes256_decrypt_hex_file_to_bytes(const unsigned char *key, const char *path, unsigned char **plaintext, size_t *plaintext_len) {
	FILE *f = fopen(path, "r");
	if (!f)
		return 0;
	if (fseek(f, 0, SEEK_END) != 0) {
		fclose(f);
		return 0;
	}
	long sz = ftell(f);
	if (sz <= 0) {
		fclose(f);
		return 0;
	}
	if (fseek(f, 0, SEEK_SET) != 0) {
		fclose(f);
		return 0;
	}
	char *buf = malloc((size_t)sz + 1);
	if (!buf) {
		fclose(f);
		return 0;
	}
	size_t read_n = fread(buf, 1, (size_t)sz, f);
	fclose(f);
	if (read_n == 0) {
		free(buf);
		return 0;
	}
	buf[read_n] = '\0';
	trim_newline(buf);
	unsigned char *plain = NULL;
	size_t len = 0;
	int ok = aes256_decrypt_hex_string_to_bytes(key, buf, &plain, &len);
	free(buf);
	if (!ok)
		return 0;
	*plaintext = plain;
	*plaintext_len = len;
	return 1;
}

static int ecdsa_sign_file_to_hex(const char *sk_path, const char *msg_path, const char *sig_out_path) {
	EC_KEY *ec_key = load_private_key_hex_file(sk_path);
	if (!ec_key)
		return 0;
	FILE *f = fopen(msg_path, "r");
	if (!f) {
		EC_KEY_free(ec_key);
		return 0;
	}
	fseek(f, 0, SEEK_END);
	long sz = ftell(f);
	if (sz < 0) {
		fclose(f);
		EC_KEY_free(ec_key);
		return 0;
	}
	fseek(f, 0, SEEK_SET);
	unsigned char *buf = malloc((size_t)sz);
	if (!buf) {
		fclose(f);
		EC_KEY_free(ec_key);
		return 0;
	}
	size_t read_n = fread(buf, 1, (size_t)sz, f);
	fclose(f);
	if (read_n != (size_t)sz) {
		free(buf);
		EC_KEY_free(ec_key);
		return 0;
	}
	unsigned int sig_len = ECDSA_size(ec_key);
	unsigned char *sig = malloc(sig_len);
	if (!sig) {
		free(buf);
		EC_KEY_free(ec_key);
		return 0;
	}
	if (ECDSA_sign(0, buf, (int)read_n, sig, &sig_len, ec_key) != 1) {
		free(buf);
		free(sig);
		EC_KEY_free(ec_key);
		return 0;
	}
	free(buf);
	EC_KEY_free(ec_key);
	int ok = write_hex_file(sig_out_path, sig, sig_len);
	free(sig);
	return ok;
}

static int ecdsa_verify_file_from_hex(const char *pk_path, const char *msg_path, const char *sig_hex_path) {
	EC_KEY *ec_key = load_public_key_hex_file(pk_path);
	if (!ec_key)
		return 0;
	FILE *f = fopen(msg_path, "r");
	if (!f) {
		EC_KEY_free(ec_key);
		return 0;
	}
	fseek(f, 0, SEEK_END);
	long sz = ftell(f);
	if (sz < 0) {
		fclose(f);
		EC_KEY_free(ec_key);
		return 0;
	}
	fseek(f, 0, SEEK_SET);
	unsigned char *buf = malloc((size_t)sz);
	if (!buf) {
		fclose(f);
		EC_KEY_free(ec_key);
		return 0;
	}
	size_t read_n = fread(buf, 1, (size_t)sz, f);
	fclose(f);
	if (read_n != (size_t)sz) {
		free(buf);
		EC_KEY_free(ec_key);
		return 0;
	}
	char *sig_hex = read_line(sig_hex_path, 1);
	if (!sig_hex) {
		free(buf);
		EC_KEY_free(ec_key);
		return 0;
	}
	unsigned char *sig = NULL;
	size_t sig_len = 0;
	if (!hex_to_bytes(sig_hex, &sig, &sig_len)) {
		free(sig_hex);
		free(buf);
		EC_KEY_free(ec_key);
		return 0;
	}
	free(sig_hex);
	int ver = ECDSA_verify(0, buf, (int)read_n, sig, (int)sig_len, ec_key);
	free(sig);
	free(buf);
	EC_KEY_free(ec_key);
	return ver == 1;
}

