#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/rand.h>

// Simple CA/key setup for the Kerberos demo.
//
// This program:
// - Generates three EC keypairs on curve secp256k1 and saves them as hex:
//     CA_SK.txt / CA_PK.txt
//     Client_SK.txt / Client_PK.txt
//     KDC_SK.txt / KDC_PK.txt
// - Generates two random 256-bit symmetric keys (SHA256(random)) and saves them as hex:
//     Key_AS_TGS.txt  (shared between AS and TGS)
//     Key_TGS_App.txt (shared between TGS and service)
//	   Key_Client_App.txt (shared between Client and serice)
// It does NOT create client–TGS or client–App session keys; those are managed separately.

static int write_hex_to_file(const char *path, const unsigned char *data, size_t len)
{
	FILE *f = fopen(path, "w");
	if (!f)
	{
		perror("fopen");
		return 0;
	}
	for (size_t i = 0; i < len; i++)
	{
		fprintf(f, "%02x", data[i]);
	}
	fprintf(f, "\n");
	fclose(f);
	return 1;
}

static int generate_ec_keypair(const char *sk_path, const char *pk_path)
{
	int ret = 0;
	EC_KEY *ec_key = NULL;
	EC_GROUP *group = NULL;
	const BIGNUM *priv = NULL;
	const EC_POINT *pub = NULL;
	unsigned char *pub_buf = NULL;
	int pub_len;

	group = EC_GROUP_new_by_curve_name(NID_secp256k1);
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
	if (BN_bn2binpad(priv, priv_buf, priv_len) != priv_len)
	{
		free(priv_buf);
		goto cleanup;
	}
	if (!write_hex_to_file(sk_path, priv_buf, priv_len))
	{
		free(priv_buf);
		goto cleanup;
	}
	free(priv_buf);

	pub_len = EC_POINT_point2buf(group, pub, POINT_CONVERSION_UNCOMPRESSED, &pub_buf, NULL);
	if (pub_len <= 0)
		goto cleanup;
	if (!write_hex_to_file(pk_path, pub_buf, (size_t)pub_len))
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

static int generate_random_sha256_key(const char *path)
{
	unsigned char rnd[32];
	unsigned char hash[SHA256_DIGEST_LENGTH];

	if (RAND_bytes(rnd, sizeof(rnd)) != 1)
		return 0;
	SHA256(rnd, sizeof(rnd), hash);
	return write_hex_to_file(path, hash, sizeof(hash));
}

int main(void)
{
	if (!generate_ec_keypair("Client_SK.txt", "Client_PK.txt"))
	{
		fprintf(stderr, "Failed to generate Client keypair\n");
		return EXIT_FAILURE;
	}
	if (!generate_ec_keypair("Client_temp_SK.txt", "Client_temp_PK.txt"))
	{
		fprintf(stderr, "Failed to generate Client temp keypair\n");
		return EXIT_FAILURE;
	}
	if (!generate_ec_keypair("KDC_SK.txt", "KDC_PK.txt"))
	{
		fprintf(stderr, "Failed to generate KDC keypair\n");
		return EXIT_FAILURE;
	}
	if (!generate_ec_keypair("AS_temp_SK.txt", "AS_temp_PK.txt"))
	{
		fprintf(stderr, "Failed to generate Client temp keypair\n");
		return EXIT_FAILURE;
	}
	if (!generate_random_sha256_key("Key_AS_TGS.txt"))
	{
		fprintf(stderr, "Failed to generate Key_AS_TGS\n");
		return EXIT_FAILURE;
	}
	if (!generate_random_sha256_key("Key_TGS_App.txt"))
	{
		fprintf(stderr, "Failed to generate Key_TGS_App\n");
		return EXIT_FAILURE;
	}
	if (!generate_random_sha256_key("Key_Client_TGS.txt"))
	{
		fprintf(stderr, "Failed to generate Key_Client_TGS\n");
		return EXIT_FAILURE;
	}
	if (!generate_random_sha256_key("Key_Client_App.txt"))
	{
		fprintf(stderr, "Failed to generate Key_Client_App\n");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}