/*
 * Copyright The Zephyr Project Contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(net_coap, CONFIG_COAP_LOG_LEVEL);

#include <errno.h>
#include <string.h>

#include <zephyr/net/coap.h>
#include <zephyr/net/coap_edhoc.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/toolchain.h>

#include <psa/crypto.h>

#include "coap_edhoc.h"

/* Cipher suite 2 uses P-256; the static Diffie-Hellman keys are 32-byte
 * X-coordinates and the private scalar is 32 bytes.
 */
#define EDHOC_P256_COORD_LEN 32U

/* ID_CRED encoded as a COSE x5t thumbprint map: {34: [-15, h'<8 bytes>']}. */
#define EDHOC_X5T_HASH_LEN   8U
#define EDHOC_X5T_ID_CRED_LEN 14U

/* Marker preceding the responder public key inside a P-256 X.509 certificate:
 * the prime256v1 named curve OID followed by the uncompressed EC point BIT
 * STRING header (0x03 0x42 0x00 0x04). The 32-byte X-coordinate follows.
 */
static const uint8_t p256_pubkey_marker[] = {
	0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
	0x03, 0x42, 0x00, 0x04,
};

/* Marker preceding the 32-byte private scalar inside a SEC1 or PKCS#8 EC
 * private key: ECPrivateKey version INTEGER 1 and the 32-byte OCTET STRING.
 */
static const uint8_t ec_privkey_marker[] = {
	0x02, 0x01, 0x01, 0x04, 0x20,
};

/* Long-lived, service-owned storage for the converted credentials. References
 * handed to the uoscore-uedhoc backend point here, so it must outlive the
 * handshake. ponytail: sized for a single EDHOC-enabled service.
 */
struct edhoc_sec_tag_store {
	uint8_t cred_r[CONFIG_COAP_EDHOC_MAX_CRED_SIZE];
	size_t cred_r_len;
	uint8_t id_cred_r[EDHOC_X5T_ID_CRED_LEN];
	uint8_t g_r[EDHOC_P256_COORD_LEN];
	uint8_t r[EDHOC_P256_COORD_LEN];
	uint8_t cred_i[CONFIG_COAP_EDHOC_MAX_CRED_SIZE];
	size_t cred_i_len;
	uint8_t id_cred_i[EDHOC_X5T_ID_CRED_LEN];
	uint8_t g_i[EDHOC_P256_COORD_LEN];
	bool valid;
};

static struct coap_edhoc_sec_tag_config sec_tag_config;
static bool sec_tag_config_set;
static struct edhoc_sec_tag_store sec_tag_store;

/* Locate a byte pattern inside a DER blob. */
static const uint8_t *der_find(const uint8_t *hay, size_t hay_len, const uint8_t *needle,
			       size_t needle_len)
{
	if (needle_len == 0U || hay_len < needle_len) {
		return NULL;
	}

	for (size_t i = 0U; i <= (hay_len - needle_len); i++) {
		if (memcmp(hay + i, needle, needle_len) == 0) {
			return hay + i;
		}
	}

	return NULL;
}

/* Extract the 32-byte static Diffie-Hellman public key (X-coordinate) from a
 * P-256 X.509 certificate.
 */
static int der_extract_g(const uint8_t *der, size_t der_len, uint8_t *out)
{
	const uint8_t *p;

	p = der_find(der, der_len, p256_pubkey_marker, sizeof(p256_pubkey_marker));
	if (p == NULL) {
		LOG_ERR("EDHOC sec_tag: no P-256 public key in certificate");
		return -EINVAL;
	}

	p += sizeof(p256_pubkey_marker);
	if ((size_t)(p - der) + EDHOC_P256_COORD_LEN > der_len) {
		return -EINVAL;
	}

	memcpy(out, p, EDHOC_P256_COORD_LEN);

	return 0;
}

/* Extract the 32-byte private scalar from a SEC1 or PKCS#8 EC private key. */
static int der_extract_scalar(const uint8_t *der, size_t der_len, uint8_t *out)
{
	const uint8_t *p;

	p = der_find(der, der_len, ec_privkey_marker, sizeof(ec_privkey_marker));
	if (p == NULL) {
		LOG_ERR("EDHOC sec_tag: unsupported private key format");
		return -EINVAL;
	}

	p += sizeof(ec_privkey_marker);
	if ((size_t)(p - der) + EDHOC_P256_COORD_LEN > der_len) {
		return -EINVAL;
	}

	memcpy(out, p, EDHOC_P256_COORD_LEN);

	return 0;
}

/* Wrap a DER certificate in a CBOR byte string to form CRED_x. */
static int cred_wrap(const uint8_t *der, size_t der_len, uint8_t *out, size_t out_cap,
		     size_t *out_len)
{
	size_t hdr_len;

	if (der_len < 24U) {
		hdr_len = 1U;
	} else if (der_len < 256U) {
		hdr_len = 2U;
	} else if (der_len < 65536U) {
		hdr_len = 3U;
	} else {
		return -EINVAL;
	}

	if ((hdr_len + der_len) > out_cap) {
		return -ENOMEM;
	}

	if (der_len < 24U) {
		out[0] = 0x40U | (uint8_t)der_len;
	} else if (der_len < 256U) {
		out[0] = 0x58U;
		out[1] = (uint8_t)der_len;
	} else {
		out[0] = 0x59U;
		out[1] = (uint8_t)(der_len >> 8);
		out[2] = (uint8_t)(der_len & 0xffU);
	}

	memcpy(out + hdr_len, der, der_len);
	*out_len = hdr_len + der_len;

	return 0;
}

/* Build ID_CRED_x as the COSE x5t thumbprint {34: [-15, h'<SHA-256/64>']}. */
static int id_cred_x5t(const uint8_t *der, size_t der_len, uint8_t *out)
{
	uint8_t digest[32];
	size_t digest_len;
	psa_status_t status;

	status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		return -EIO;
	}

	status = psa_hash_compute(PSA_ALG_SHA_256, der, der_len, digest, sizeof(digest),
				  &digest_len);
	if (status != PSA_SUCCESS || digest_len < EDHOC_X5T_HASH_LEN) {
		return -EIO;
	}

	out[0] = 0xa1U; /* map(1) */
	out[1] = 0x18U; /* uint ... */
	out[2] = 0x22U; /* ... 34 (x5t) */
	out[3] = 0x82U; /* array(2) */
	out[4] = 0x2eU; /* -15 (SHA-256/64) */
	out[5] = 0x48U; /* bstr(8) */
	memcpy(out + 6, digest, EDHOC_X5T_HASH_LEN);

	return 0;
}

/* Fetch a credential blob using a two-pass size query then retrieval. */
static int fetch_cred(sec_tag_t tag, enum tls_credential_type type, uint8_t *buf, size_t cap,
		      size_t *len)
{
	size_t need = 0U;
	int ret;

	ret = tls_credential_get(tag, type, NULL, &need);
	if (ret == -ENOENT) {
		return -ENOENT;
	}
	if (ret != -EFBIG || need == 0U) {
		LOG_ERR("EDHOC sec_tag: bad credential (tag %d type %d ret %d)", tag, (int)type,
			ret);
		return -EINVAL;
	}
	if (need > cap) {
		LOG_ERR("EDHOC sec_tag: credential too large (%zu > %zu)", need, cap);
		return -EFBIG;
	}

	*len = cap;
	ret = tls_credential_get(tag, type, buf, len);
	if (ret < 0) {
		return ret;
	}

	return 0;
}

/* Convert one certificate into the CRED, ID_CRED and static DH public key. */
static int convert_cert(sec_tag_t tag, enum tls_credential_type type, uint8_t *cred, size_t cred_cap,
			size_t *cred_len, uint8_t *id_cred, uint8_t *g)
{
	uint8_t der[CONFIG_COAP_EDHOC_MAX_DER_SIZE];
	size_t der_len;
	int ret;

	ret = fetch_cred(tag, type, der, sizeof(der), &der_len);
	if (ret < 0) {
		return ret;
	}

	ret = der_extract_g(der, der_len, g);
	if (ret < 0) {
		return ret;
	}

	ret = cred_wrap(der, der_len, cred, cred_cap, cred_len);
	if (ret < 0) {
		return ret;
	}

	return id_cred_x5t(der, der_len, id_cred);
}

/* Fetch and extract the responder private scalar. */
static int convert_privkey(sec_tag_t tag, uint8_t *r)
{
	uint8_t der[CONFIG_COAP_EDHOC_MAX_DER_SIZE];
	size_t der_len;
	int ret;

	ret = fetch_cred(tag, TLS_CREDENTIAL_PRIVATE_KEY, der, sizeof(der), &der_len);
	if (ret < 0) {
		return ret;
	}

	ret = der_extract_scalar(der, der_len, r);
	(void)memset(der, 0, sizeof(der));

	return ret;
}

/* Fetch and convert all sec_tag material into the long-lived store. */
static int sec_tag_convert(struct edhoc_sec_tag_store *store)
{
	int ret;

	/* Responder certificate: CRED_R, ID_CRED_R and G_R. */
	ret = convert_cert(sec_tag_config.responder_sec_tag, TLS_CREDENTIAL_PUBLIC_CERTIFICATE,
			   store->cred_r, sizeof(store->cred_r), &store->cred_r_len,
			   store->id_cred_r, store->g_r);
	if (ret < 0) {
		return ret;
	}

	/* Responder private key: R. */
	ret = convert_privkey(sec_tag_config.responder_sec_tag, store->r);
	if (ret < 0) {
		return ret;
	}

	/* Trusted initiator certificate: CRED_I, ID_CRED_I and G_I. Accept the
	 * peer material from a CA slot first, then a public certificate slot.
	 */
	ret = convert_cert(sec_tag_config.initiator_sec_tag, TLS_CREDENTIAL_CA_CERTIFICATE,
			   store->cred_i, sizeof(store->cred_i), &store->cred_i_len,
			   store->id_cred_i, store->g_i);
	if (ret == -ENOENT) {
		ret = convert_cert(sec_tag_config.initiator_sec_tag,
				   TLS_CREDENTIAL_PUBLIC_CERTIFICATE, store->cred_i,
				   sizeof(store->cred_i), &store->cred_i_len, store->id_cred_i,
				   store->g_i);
	}
	if (ret < 0) {
		return ret;
	}

	store->valid = true;

	return 0;
}

static void sec_tag_populate(const struct edhoc_sec_tag_store *store,
			     struct coap_edhoc_credentials *creds)
{
	creds->id_cred_r = store->id_cred_r;
	creds->id_cred_r_len = sizeof(store->id_cred_r);
	creds->cred_r = store->cred_r;
	creds->cred_r_len = store->cred_r_len;
	creds->g_r = store->g_r;
	creds->g_r_len = sizeof(store->g_r);
	creds->r = store->r;
	creds->r_len = sizeof(store->r);

	creds->id_cred_i = store->id_cred_i;
	creds->id_cred_i_len = sizeof(store->id_cred_i);
	creds->cred_i = store->cred_i;
	creds->cred_i_len = store->cred_i_len;
	creds->g_i = store->g_i;
	creds->g_i_len = sizeof(store->g_i);
}

static int sec_tag_load(struct coap_edhoc_credentials *creds)
{
	int ret;

	if (!sec_tag_store.valid) {
		ret = sec_tag_convert(&sec_tag_store);
		if (ret < 0) {
			return ret;
		}
	}

	sec_tag_populate(&sec_tag_store, creds);

	return 0;
}

int coap_edhoc_set_sec_tag_config(const struct coap_edhoc_sec_tag_config *config)
{
	if (config == NULL) {
		sec_tag_config_set = false;
	} else {
		sec_tag_config = *config;
		sec_tag_config_set = true;
	}

	/* Force a re-conversion on the next handshake. */
	(void)memset(&sec_tag_store, 0, sizeof(sec_tag_store));

	return 0;
}

int coap_edhoc_acquire_credentials(struct coap_edhoc_credentials *creds)
{
	if (creds == NULL) {
		return -EINVAL;
	}

	if (!sec_tag_config_set) {
		LOG_WRN("EDHOC credentials not available (no sec_tag configured)");
		return -ENOENT;
	}

	return sec_tag_load(creds);
}

int coap_edhoc_encode_error(int err_code, const char *diag_msg,
			    uint8_t *out_buf, size_t *inout_len)
{
	size_t diag_len;
	size_t tstr_header_len;
	size_t offset = 0U;

	if (out_buf == NULL || inout_len == NULL || diag_msg == NULL) {
		return -EINVAL;
	}

	/* Only single-byte CBOR unsigned integers are supported for ERR_CODE. */
	if (err_code < 0 || err_code > 23) {
		LOG_ERR("Unsupported EDHOC error code %d (must be 0..23)", err_code);
		return -EINVAL;
	}

	diag_len = strlen(diag_msg);
	if (diag_len < 24U) {
		tstr_header_len = 1U;
	} else if (diag_len < 256U) {
		tstr_header_len = 2U;
	} else if (diag_len < 65536U) {
		tstr_header_len = 3U;
	} else {
		LOG_ERR("EDHOC diagnostic message too long (%zu bytes)", diag_len);
		return -EINVAL;
	}

	if (*inout_len < (1U + tstr_header_len + diag_len)) {
		return -ENOMEM;
	}

	/* ERR_CODE: CBOR unsigned integer (major type 0). */
	out_buf[offset++] = (uint8_t)err_code;

	/* ERR_INFO: CBOR text string (major type 3). */
	if (diag_len < 24U) {
		out_buf[offset++] = 0x60U | (uint8_t)diag_len;
	} else if (diag_len < 256U) {
		out_buf[offset++] = 0x78U;
		out_buf[offset++] = (uint8_t)diag_len;
	} else {
		out_buf[offset++] = 0x79U;
		out_buf[offset++] = (uint8_t)(diag_len >> 8);
		out_buf[offset++] = (uint8_t)(diag_len & 0xffU);
	}

	memcpy(out_buf + offset, diag_msg, diag_len);
	offset += diag_len;

	*inout_len = offset;

	return 0;
}
