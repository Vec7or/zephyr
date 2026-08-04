/*
 * Copyright The Zephyr Project Contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file
 * @brief Internal EDHOC helpers for CoAP (RFC 9668 / RFC 9528).
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

/** A non-owning view into a contiguous byte range. */
struct coap_edhoc_span {
	const uint8_t *ptr; /**< Pointer to the first byte. */
	size_t len;         /**< Number of bytes. */
};

/**
 * @brief Check whether a CoAP packet carries the EDHOC option (21).
 *
 * Detection only; validation of the "at most once" rule is done by
 * @ref coap_edhoc_validate_option.
 *
 * @param cpkt CoAP packet to inspect.
 *
 * @return true if at least one EDHOC option is present, false otherwise.
 */
bool coap_edhoc_msg_has_edhoc(const struct coap_packet *cpkt);

/**
 * @brief Validate the EDHOC option occurrence per RFC 9668 Section 3.1.
 *
 * The EDHOC option MUST occur at most once. Its value is ignored.
 *
 * @param cpkt    CoAP packet to inspect.
 * @param present Set to true if at least one EDHOC option is present.
 *
 * @return 0 if zero or one EDHOC option is present.
 * @return -EBADMSG if more than one EDHOC option is present.
 * @return -EINVAL on invalid arguments.
 */
int coap_edhoc_validate_option(const struct coap_packet *cpkt, bool *present);

/**
 * @brief Split an EDHOC+OSCORE combined payload per RFC 9668 Section 3.2.1.
 *
 * COMB_PAYLOAD = EDHOC_MSG_3 (a CBOR byte string) followed by OSCORE_PAYLOAD.
 * Both parts MUST be present.
 *
 * @param payload       Combined payload bytes.
 * @param payload_len   Length of @p payload.
 * @param edhoc_msg3    Output span pointing at the EDHOC message_3 CBOR bstr.
 * @param oscore_payload Output span pointing at the trailing OSCORE payload.
 *
 * @return 0 on success, -EINVAL on malformed input.
 */
int coap_edhoc_split_comb_payload(const uint8_t *payload, size_t payload_len,
				  struct coap_edhoc_span *edhoc_msg3,
				  struct coap_edhoc_span *oscore_payload);

/**
 * @brief Remove the EDHOC option (21) from a CoAP packet.
 *
 * @param cpkt Packet to modify in place.
 *
 * @return 0 on success or if the option was absent, negative errno otherwise.
 */
int coap_edhoc_remove_option(struct coap_packet *cpkt);

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
