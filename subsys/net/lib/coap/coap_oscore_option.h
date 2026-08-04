/*
 * Copyright The Zephyr Project Contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file
 * @brief Helpers to parse the OSCORE option value (RFC 8613 Section 6.1).
 */

#ifndef ZEPHYR_SUBSYS_NET_LIB_COAP_COAP_OSCORE_OPTION_H_
#define ZEPHYR_SUBSYS_NET_LIB_COAP_COAP_OSCORE_OPTION_H_

#include <stddef.h>
#include <stdint.h>

#include <zephyr/net/coap.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Extract the OSCORE 'kid' field from a CoAP packet's OSCORE option.
 *
 * Parses the OSCORE option value per RFC 8613 Section 6.1: flag byte (n in bits
 * 0-2, k in bit 3, h in bit 4, bits 5-7 reserved), optional Partial IV of n raw
 * bytes, optional 1-byte-prefixed kid context, and the kid as the remaining
 * bytes. Malformed values are rejected fail-closed.
 *
 * For an EDHOC+OSCORE combined request the kid equals the responder connection
 * identifier C_R (RFC 9668 Section 3.2.2).
 *
 * @param cpkt    CoAP packet containing an OSCORE option.
 * @param kid     Output buffer for the kid bytes.
 * @param kid_len In: capacity of @p kid. Out: number of kid bytes written.
 *
 * @return 0 on success.
 * @return -ENOENT if no OSCORE option or no kid (k flag clear) is present.
 * @return -ENOMEM if the kid does not fit in @p kid.
 * @return -EINVAL on malformed option or invalid arguments.
 */
int coap_oscore_option_extract_kid(const struct coap_packet *cpkt,
				   uint8_t *kid, size_t *kid_len);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_NET_LIB_COAP_COAP_OSCORE_OPTION_H_ */
