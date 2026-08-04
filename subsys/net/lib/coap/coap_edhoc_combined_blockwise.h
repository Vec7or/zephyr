/*
 * Copyright The Zephyr Project Contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file
 * @brief Outer Block1 reassembly for EDHOC+OSCORE combined requests.
 *
 * Implements RFC 9668 Section 3.3.2 Step 0: reassembly of a combined request
 * transferred with outer Block1, keyed by (address, token, Request-Tag list)
 * per RFC 9175.
 */

#ifndef ZEPHYR_SUBSYS_NET_LIB_COAP_COAP_EDHOC_COMBINED_BLOCKWISE_H_
#define ZEPHYR_SUBSYS_NET_LIB_COAP_COAP_EDHOC_COMBINED_BLOCKWISE_H_

#include <stddef.h>
#include <stdint.h>

#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zephyr/net/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Result of coap_edhoc_outer_block_process(). */
enum coap_edhoc_outer_block_result {
	/** Not an outer-Block1 combined request; caller proceeds normally. */
	COAP_EDHOC_OUTER_BLOCK_PASS = 0,
	/** Intermediate block accepted, 2.31 Continue sent; wait for more. */
	COAP_EDHOC_OUTER_BLOCK_WAITING,
	/** Reassembly complete; @p out_buf holds the full combined request. */
	COAP_EDHOC_OUTER_BLOCK_COMPLETE,
	/** Error; an error response was already sent. */
	COAP_EDHOC_OUTER_BLOCK_ERROR,
};

/**
 * @brief Process a possibly outer-Block1-fragmented combined request.
 *
 * @param service   Owning CoAP service.
 * @param request   Parsed incoming request.
 * @param in_buf    Raw received bytes backing @p request.
 * @param in_len    Length of @p in_buf.
 * @param addr      Client address.
 * @param addr_len  Client address length.
 * @param out_buf   Buffer to receive the reassembled request on completion.
 * @param out_size  Capacity of @p out_buf.
 * @param out_len   On completion, the reassembled length.
 *
 * @return A ::coap_edhoc_outer_block_result value.
 */
int coap_edhoc_outer_block_process(const struct coap_service *service, struct coap_packet *request,
				   const uint8_t *in_buf, size_t in_len,
				   const struct net_sockaddr *addr, net_socklen_t addr_len,
				   uint8_t *out_buf, size_t out_size, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_NET_LIB_COAP_COAP_EDHOC_COMBINED_BLOCKWISE_H_ */
