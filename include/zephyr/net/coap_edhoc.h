/*
 * Copyright The Zephyr Project Contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file
 * @brief CoAP EDHOC API
 *
 * Configuration of the EDHOC (@rfc{9528}) responder exposed by the CoAP
 * server at /.well-known/edhoc.
 */

#ifndef ZEPHYR_INCLUDE_NET_COAP_EDHOC_H_
#define ZEPHYR_INCLUDE_NET_COAP_EDHOC_H_

#include <zephyr/net/tls_credentials.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief CoAP EDHOC API
 * @defgroup coap_edhoc CoAP EDHOC API
 * @since 4.5
 * @version 0.1.0
 * @ingroup networking
 * @{
 */

/**
 * @brief TLS credential tags holding the EDHOC credentials.
 *
 * @kconfig_dep{CONFIG_COAP_EDHOC}
 */
struct coap_edhoc_sec_tag_config {
	/** Tag holding the responder X.509 certificate and P-256 private key. */
	sec_tag_t responder_sec_tag;
	/** Tag holding the trusted initiator X.509 certificate. */
	sec_tag_t initiator_sec_tag;
};

/**
 * @brief Select the credentials used by the EDHOC responder.
 *
 * The configuration is copied. The referenced credentials are fetched and
 * converted on the next handshake.
 *
 * @kconfig_dep{CONFIG_COAP_EDHOC}
 *
 * @param config Credential tags, or NULL to clear the configuration.
 *
 * @retval 0 on success.
 */
int coap_edhoc_set_sec_tag_config(const struct coap_edhoc_sec_tag_config *config);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_NET_COAP_EDHOC_H_ */
