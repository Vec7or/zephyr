/*
 * Copyright The Zephyr Project Contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file
 * @brief Internal EDHOC helpers for CoAP (RFC 9528).
 */

#ifndef ZEPHYR_SUBSYS_NET_LIB_COAP_COAP_EDHOC_H_
#define ZEPHYR_SUBSYS_NET_LIB_COAP_COAP_EDHOC_H_

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include <zephyr/net/coap.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief EDHOC responder credentials (RFC 9528, method 3, cipher suite 2).
 *
 * Internal carrier populated from sec_tag TLS credential storage and consumed
 * by the EDHOC transport. All buffers are referenced (not copied) and point
 * into long-lived, service-owned storage.
 */
struct coap_edhoc_credentials {
	/** Responder ID_CRED_R (COSE header identifying CRED_R). */
	const uint8_t *id_cred_r;
	/** Length of @ref id_cred_r. */
	size_t id_cred_r_len;
	/** Responder CRED_R (CBOR-encoded credential). */
	const uint8_t *cred_r;
	/** Length of @ref cred_r. */
	size_t cred_r_len;
	/** Responder static Diffie-Hellman public key G_R. */
	const uint8_t *g_r;
	/** Length of @ref g_r. */
	size_t g_r_len;
	/** Responder static Diffie-Hellman private key R. */
	const uint8_t *r;
	/** Length of @ref r. */
	size_t r_len;

	/** Trusted initiator ID_CRED_I (COSE header identifying CRED_I). */
	const uint8_t *id_cred_i;
	/** Length of @ref id_cred_i. */
	size_t id_cred_i_len;
	/** Trusted initiator CRED_I (CBOR-encoded credential). */
	const uint8_t *cred_i;
	/** Length of @ref cred_i. */
	size_t cred_i_len;
	/** Trusted initiator static Diffie-Hellman public key G_I. */
	const uint8_t *g_i;
	/** Length of @ref g_i. */
	size_t g_i_len;
};

/**
 * @brief Acquire the EDHOC responder credentials for a handshake.
 *
 * Fetches the material referenced by the sec_tag configuration installed
 * through coap_edhoc_set_sec_tag_config() and converts it into @p creds.
 *
 * @param creds Output structure populated with credential references.
 *
 * @return 0 on success, negative errno on failure (-ENOENT if no configuration
 *         has been installed).
 */
int coap_edhoc_acquire_credentials(struct coap_edhoc_credentials *creds);

/**
 * @brief Encode an EDHOC error message as a CBOR sequence (RFC 9528 Section 6).
 *
 * error = (ERR_CODE : int, ERR_INFO : any). For ERR_CODE = 1 (Unspecified
 * Error) ERR_INFO is a text string diagnostic message.
 *
 * @param err_code  EDHOC error code (supported range 0..23).
 * @param diag_msg  Diagnostic text (ERR_INFO), must not be NULL.
 * @param out_buf   Output buffer.
 * @param inout_len In: capacity of @p out_buf. Out: encoded length.
 *
 * @return 0 on success, -ENOMEM if the buffer is too small, -EINVAL otherwise.
 */
int coap_edhoc_encode_error(int err_code, const char *diag_msg,
			    uint8_t *out_buf, size_t *inout_len);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_NET_LIB_COAP_COAP_EDHOC_H_ */
