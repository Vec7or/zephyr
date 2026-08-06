/*
 * Copyright The Zephyr Project Contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file
 * @brief EDHOC over CoAP transport at /.well-known/edhoc (RFC 9528 App A.2).
 */

#ifndef ZEPHYR_SUBSYS_NET_LIB_COAP_COAP_EDHOC_TRANSPORT_H_
#define ZEPHYR_SUBSYS_NET_LIB_COAP_COAP_EDHOC_TRANSPORT_H_

#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zephyr/net/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

/** URI path of the EDHOC resource (RFC 9528 Appendix A.2). */
#define COAP_WELL_KNOWN_EDHOC_PATH ((const char *const[]){".well-known", "edhoc", NULL})

/**
 * @brief Handle a request to the /.well-known/edhoc resource.
 *
 * Implements the RFC 9528 Appendix A.2 forward message flow (message_1 and
 * message_3 from the initiator, message_2 and optional message_4 in the
 * responses). On completion of message_3 the derived OSCORE context is cached
 * for subsequent EDHOC+OSCORE combined requests.
 *
 * A response (2.04 Changed or an EDHOC/CoAP error) is sent internally.
 *
 * @param service  Owning CoAP service.
 * @param request  Parsed incoming request.
 * @param addr     Client address.
 * @param addr_len Client address length.
 *
 * @return 0 on success (response sent), negative errno on internal failure.
 */
int coap_edhoc_transport_handle_request(const struct coap_service *service,
					struct coap_packet *request,
					const struct net_sockaddr *addr, net_socklen_t addr_len);

#if defined(CONFIG_ZTEST)
/**
 * @brief Validate the EDHOC request Content-Format (RFC 9528 Appendix A.2).
 *
 * Exposed for testing. Requires exactly one Content-Format option equal to
 * application/cid-edhoc+cbor-seq (65).
 *
 * @return 0 if valid, -ENOENT if missing, -EMSGSIZE if duplicated,
 *         -EBADMSG if the value is not 65.
 */
int coap_edhoc_transport_validate_content_format(const struct coap_packet *request);
#endif

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_NET_LIB_COAP_COAP_EDHOC_TRANSPORT_H_ */
