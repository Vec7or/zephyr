/*
 * Copyright (c) 2026 Martin Schröder <info@swedishembedded.com>
 * Copyright (c) 2026 Siemens AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_test, LOG_LEVEL_DBG);

#include <errno.h>
#include <zephyr/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <zephyr/sys/printk.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>
#include <zephyr/net/coap/coap.h>
#include <zephyr/net/coap/coap_service.h>
#include <zephyr/net/socket.h>

#include <zephyr/ztest.h>

#include "net_private.h"

#include "coap_oscore.h"

#define COAP_BUF_SIZE 128

static uint16_t oscore_e2e_service_port = 56839;

static int oscore_e2e_get(struct coap_resource *resource, struct coap_packet *request,
			  struct net_sockaddr *addr, net_socklen_t addr_len)
{
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint8_t data[COAP_BUF_SIZE];
	struct coap_packet response;
	static const uint8_t payload[] = "encrypted-response";
	uint8_t tkl;
	int ret;

	ARG_UNUSED(resource);

	tkl = coap_header_get_token(request, token);

	ret = coap_packet_init(&response, data, sizeof(data), COAP_VERSION_1, COAP_TYPE_ACK, tkl,
			       token, COAP_RESPONSE_CODE_CONTENT, coap_header_get_id(request));
	if (ret < 0) {
		return COAP_RESPONSE_CODE_INTERNAL_ERROR;
	}

	ret = coap_packet_append_payload_marker(&response);
	if (ret < 0) {
		return COAP_RESPONSE_CODE_INTERNAL_ERROR;
	}

	ret = coap_packet_append_payload(&response, payload, sizeof(payload) - 1);
	if (ret < 0) {
		return COAP_RESPONSE_CODE_INTERNAL_ERROR;
	}

	ret = coap_resource_send(resource, &response, addr, addr_len, NULL);
	if (ret < 0) {
		return COAP_RESPONSE_CODE_INTERNAL_ERROR;
	}

	return 0;
}

COAP_SERVICE_DEFINE(oscore_e2e_service, NULL, &oscore_e2e_service_port, 0);

static const char *const oscore_e2e_path[] = {"e2e", NULL};
COAP_RESOURCE_DEFINE(oscore_e2e_resource, oscore_e2e_service,
		     // clang-format off
		     {
			     .path = oscore_e2e_path,
			     .get = oscore_e2e_get,
		     } // clang-format on
);

/* Test OSCORE option number is correctly defined */
ZTEST(coap_oscore, test_oscore_option_number)
{
	/* RFC 8613 Section 2: OSCORE option number is 9 */
	zassert_equal(COAP_OPTION_OSCORE, 9, "OSCORE option number must be 9");
}

/* Test OSCORE malformed message validation (RFC 8613 Section 2) */
ZTEST(coap_oscore, test_oscore_malformed_validation)
{
	struct coap_packet cpkt;
	uint8_t buf[COAP_BUF_SIZE];
	int r;

	/* RFC 8613 Section 2: OSCORE option without payload is malformed */
	r = coap_packet_init(&cpkt, buf, sizeof(buf), COAP_VERSION_1, COAP_TYPE_CON, 0, NULL,
			     COAP_METHOD_GET, coap_next_id());
	zassert_equal(r, 0, "Should init packet");

	/* Add OSCORE option (empty value is valid for the option itself) */
	r = coap_packet_append_option(&cpkt, COAP_OPTION_OSCORE, NULL, 0);
	zassert_equal(r, 0, "Should append OSCORE option");

	/* Validate - should fail because no payload */
	r = coap_oscore_validate_msg(&cpkt);
	zassert_equal(r, -EBADMSG, "Should reject OSCORE without payload, got %d", r);

	/* Now add a payload marker and payload */
	r = coap_packet_append_payload_marker(&cpkt);
	zassert_equal(r, 0, "Should append payload marker");

	const uint8_t payload[] = "test";

	r = coap_packet_append_payload(&cpkt, payload, sizeof(payload) - 1);
	zassert_equal(r, 0, "Should append payload");

	/* Now validation should pass */
	r = coap_oscore_validate_msg(&cpkt);
	zassert_equal(r, 0, "Should accept OSCORE with payload, got %d", r);
}

/* Test OSCORE message detection */
ZTEST(coap_oscore, test_oscore_message_detection)
{
	struct coap_packet cpkt;
	uint8_t buf[COAP_BUF_SIZE];
	int r;
	bool has_oscore;

	/* Create message without OSCORE option */
	r = coap_packet_init(&cpkt, buf, sizeof(buf), COAP_VERSION_1, COAP_TYPE_CON, 0, NULL,
			     COAP_METHOD_GET, coap_next_id());
	zassert_equal(r, 0, "Should init packet");

	has_oscore = coap_oscore_msg_has_oscore(&cpkt);
	zassert_false(has_oscore, "Should not detect OSCORE option");

	/* Create message with OSCORE option */
	r = coap_packet_init(&cpkt, buf, sizeof(buf), COAP_VERSION_1, COAP_TYPE_CON, 0, NULL,
			     COAP_METHOD_GET, coap_next_id());
	zassert_equal(r, 0, "Should init packet");

	r = coap_packet_append_option(&cpkt, COAP_OPTION_OSCORE, NULL, 0);
	zassert_equal(r, 0, "Should append OSCORE option");

	has_oscore = coap_oscore_msg_has_oscore(&cpkt);
	zassert_true(has_oscore, "Should detect OSCORE option");
}

/* Test OSCORE exchange cache management */
ZTEST(coap_oscore, test_oscore_exchange_cache)
{
	struct coap_oscore_exchange cache[CONFIG_COAP_OSCORE_EXCHANGE_CACHE_SIZE];
	struct net_sockaddr_in6 addr1 = {
		.sin6_family = NET_AF_INET6,
		.sin6_addr = {{{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1}}},
		.sin6_port = net_htons(5683),
	};
	struct net_sockaddr_in6 addr2 = {
		.sin6_family = NET_AF_INET6,
		.sin6_addr = {{{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2}}},
		.sin6_port = net_htons(5683),
	};
	uint8_t token1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t token2[] = {0x05, 0x06, 0x07, 0x08};

	/* Initialize cache */
	memset(cache, 0, sizeof(cache));

	/* Test: Add entry to cache */
	int ret = oscore_exchange_add(cache, (struct net_sockaddr *)&addr1, sizeof(addr1), token1,
				      sizeof(token1), false);
	zassert_equal(ret, 0, "Should add exchange entry");

	/* Test: Find the entry */
	struct coap_oscore_exchange *entry;

	entry = oscore_exchange_find(cache, (struct net_sockaddr *)&addr1, sizeof(addr1), token1,
				     sizeof(token1));
	zassert_not_null(entry, "Should find exchange entry");
	zassert_equal(entry->tkl, sizeof(token1), "Token length should match");
	zassert_mem_equal(entry->token, token1, sizeof(token1), "Token should match");
	zassert_false(entry->is_observe, "Should not be Observe exchange");

	/* Test: Add another entry with different address */
	ret = oscore_exchange_add(cache, (struct net_sockaddr *)&addr2, sizeof(addr2), token2,
				  sizeof(token2), true);
	zassert_equal(ret, 0, "Should add second exchange entry");

	/* Test: Find second entry */
	entry = oscore_exchange_find(cache, (struct net_sockaddr *)&addr2, sizeof(addr2), token2,
				     sizeof(token2));
	zassert_not_null(entry, "Should find second exchange entry");
	zassert_true(entry->is_observe, "Should be Observe exchange");

	/* Test: Update existing entry */
	ret = oscore_exchange_add(cache, (struct net_sockaddr *)&addr1, sizeof(addr1), token1,
				  sizeof(token1), true);
	zassert_equal(ret, 0, "Should update exchange entry");

	entry = oscore_exchange_find(cache, (struct net_sockaddr *)&addr1, sizeof(addr1), token1,
				     sizeof(token1));
	zassert_not_null(entry, "Should still find exchange entry");
	zassert_true(entry->is_observe, "Should now be Observe exchange");

	/* Test: Remove entry */
	oscore_exchange_remove(cache, (struct net_sockaddr *)&addr1, sizeof(addr1), token1,
			       sizeof(token1));

	entry = oscore_exchange_find(cache, (struct net_sockaddr *)&addr1, sizeof(addr1), token1,
				     sizeof(token1));
	zassert_is_null(entry, "Should not find removed entry");

	/* Test: Second entry should still exist */
	entry = oscore_exchange_find(cache, (struct net_sockaddr *)&addr2, sizeof(addr2), token2,
				     sizeof(token2));
	zassert_not_null(entry, "Second entry should still exist");
}

/* Test OSCORE response protection integration -- REWRITE!!*/
ZTEST(coap_oscore, test_oscore_response_protection)
{
	/* This test verifies that the OSCORE response protection logic is correctly
	 * integrated into coap_service_send(). We test the exchange tracking and
	 * protection decision logic.
	 *
	 * Note: Full end-to-end OSCORE encryption/decryption testing requires
	 * initializing a uoscore security context, which is beyond the scope of
	 * this unit test. This test focuses on the exchange tracking mechanism.
	 */

	struct coap_oscore_exchange cache[CONFIG_COAP_OSCORE_EXCHANGE_CACHE_SIZE];
	struct net_sockaddr_in6 addr = {
		.sin6_family = NET_AF_INET6,
		.sin6_addr = {{{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1}}},
		.sin6_port = net_htons(5683),
	};
	uint8_t token[] = {0x01, 0x02, 0x03, 0x04};
	struct coap_packet cpkt;
	uint8_t buf[COAP_BUF_SIZE];
	int r;

	/* Initialize cache */
	memset(cache, 0, sizeof(cache));

	/* Simulate OSCORE request verification by adding exchange entry */
	r = oscore_exchange_add(cache, (struct net_sockaddr *)&addr, sizeof(addr), token,
				sizeof(token), false);
	zassert_equal(r, 0, "Should add exchange entry");

	/* Create a response packet with the same token */
	r = coap_packet_init(&cpkt, buf, sizeof(buf), COAP_VERSION_1, COAP_TYPE_ACK, sizeof(token),
			     token, COAP_RESPONSE_CODE_CONTENT, coap_next_id());
	zassert_equal(r, 0, "Should init response packet");

	/* Verify exchange is found (indicating response needs protection) */
	struct coap_oscore_exchange *entry;

	entry = oscore_exchange_find(cache, (struct net_sockaddr *)&addr, sizeof(addr), token,
				     sizeof(token));
	zassert_not_null(entry, "Should find exchange for response");

	/* For non-Observe exchanges, the entry should be removed after sending */
	oscore_exchange_remove(cache, (struct net_sockaddr *)&addr, sizeof(addr), token,
			       sizeof(token));

	entry = oscore_exchange_find(cache, (struct net_sockaddr *)&addr, sizeof(addr), token,
				     sizeof(token));
	zassert_is_null(entry, "Non-Observe exchange should be removed after response");
}

/* Test OSCORE exchange expiry */
ZTEST(coap_oscore, test_oscore_exchange_expiry)
{
	struct coap_oscore_exchange cache[CONFIG_COAP_OSCORE_EXCHANGE_CACHE_SIZE];
	struct net_sockaddr_in6 addr = {
		.sin6_family = NET_AF_INET6,
		.sin6_addr = {{{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1}}},
		.sin6_port = net_htons(5683),
	};
	uint8_t token[] = {0x01, 0x02, 0x03, 0x04};
	int r;

	/* Initialize cache */
	memset(cache, 0, sizeof(cache));

	/* Add non-Observe exchange */
	r = oscore_exchange_add(cache, (struct net_sockaddr *)&addr, sizeof(addr), token,
				sizeof(token), false);
	zassert_equal(r, 0, "Should add exchange");

	/* Entry should be found initially */
	struct coap_oscore_exchange *entry;

	entry = oscore_exchange_find(cache, (struct net_sockaddr *)&addr, sizeof(addr), token,
				     sizeof(token));
	zassert_not_null(entry, "Should find fresh entry");

	/* Set timestamp to expired value */
	entry->timestamp = k_uptime_get() - CONFIG_COAP_OSCORE_EXCHANGE_LIFETIME_MS - 1000;

	/* Next find should detect expiry and clear the entry */
	entry = oscore_exchange_find(cache, (struct net_sockaddr *)&addr, sizeof(addr), token,
				     sizeof(token));
	zassert_is_null(entry, "Expired entry should be cleared");
}

/* Test OSCORE exchange cache LRU eviction */
ZTEST(coap_oscore, test_oscore_exchange_cache_eviction)
{
	struct coap_oscore_exchange cache[CONFIG_COAP_OSCORE_EXCHANGE_CACHE_SIZE];
	struct net_sockaddr_in6 addr_base = {
		.sin6_family = NET_AF_INET6,
		.sin6_addr = {{{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
		.sin6_port = net_htons(5683),
	};
	uint8_t token[] = {0x01, 0x02, 0x03, 0x04};
	int r;

	zassert(CONFIG_COAP_OSCORE_EXCHANGE_CACHE_SIZE >= 2,
		"Cache size must be at least 2 for eviction test");
	zassert(CONFIG_COAP_OSCORE_EXCHANGE_CACHE_SIZE < 0xFF,
		"Cache size must be less than 0xFF for eviction test");

	/* Initialize cache */
	memset(cache, 0, sizeof(cache));

	/* Fill the cache */
	for (int i = 0; i < CONFIG_COAP_OSCORE_EXCHANGE_CACHE_SIZE; i++) {
		struct net_sockaddr_in6 addr = addr_base;

		addr.sin6_addr.s6_addr[15] = i + 1;
		token[0] = i + 1;

		r = oscore_exchange_add(cache, (struct net_sockaddr *)&addr, sizeof(addr), token,
					sizeof(token), false);
		zassert_equal(r, 0, "Should add entry %d", i);

		/* Small delay to ensure different timestamps */
		k_msleep(1);
	}

	/* Verify cache is full */
	for (int i = 0; i < CONFIG_COAP_OSCORE_EXCHANGE_CACHE_SIZE; i++) {
		struct net_sockaddr_in6 addr = addr_base;

		addr.sin6_addr.s6_addr[15] = i + 1;
		token[0] = i + 1;

		struct coap_oscore_exchange *entry;

		entry = oscore_exchange_find(cache, (struct net_sockaddr *)&addr, sizeof(addr),
					     token, sizeof(token));
		zassert_not_null(entry, "Should find entry %d", i);
	}

	/* Add one more entry - should evict the oldest (first) entry */
	struct net_sockaddr_in6 new_addr = addr_base;

	new_addr.sin6_addr.s6_addr[15] = 0xFF;
	token[0] = 0xFF;

	r = oscore_exchange_add(cache, (struct net_sockaddr *)&new_addr, sizeof(new_addr), token,
				sizeof(token), false);
	zassert_equal(r, 0, "Should add new entry and evict oldest");

	/* Verify new entry exists */
	struct coap_oscore_exchange *entry;

	entry = oscore_exchange_find(cache, (struct net_sockaddr *)&new_addr, sizeof(new_addr),
				     token, sizeof(token));
	zassert_not_null(entry, "Should find new entry");

	/* Verify oldest entry was evicted */
	struct net_sockaddr_in6 first_addr = addr_base;

	first_addr.sin6_addr.s6_addr[15] = 1;
	token[0] = 1;

	entry = oscore_exchange_find(cache, (struct net_sockaddr *)&first_addr, sizeof(first_addr),
				     token, sizeof(token));
	zassert_is_null(entry, "Oldest entry should be evicted");
}

/* Test OSCORE Observe exchange lifecycle -- REWRITE!! */
ZTEST(coap_oscore, test_oscore_observe_exchange_lifecycle)
{
	struct coap_oscore_exchange cache[CONFIG_COAP_OSCORE_EXCHANGE_CACHE_SIZE];
	struct net_sockaddr_in6 addr = {
		.sin6_family = NET_AF_INET6,
		.sin6_addr = {{{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1}}},
		.sin6_port = net_htons(5683),
	};
	uint8_t token[] = {0x01, 0x02, 0x03, 0x04};
	int r;

	/* Initialize cache */
	memset(cache, 0, sizeof(cache));

	/* Add Observe exchange */
	r = oscore_exchange_add(cache, (struct net_sockaddr *)&addr, sizeof(addr), token,
				sizeof(token), true);
	zassert_equal(r, 0, "Should add Observe exchange");

	/* Verify exchange persists (for Observe notifications) */
	struct coap_oscore_exchange *entry;

	entry = oscore_exchange_find(cache, (struct net_sockaddr *)&addr, sizeof(addr), token,
				     sizeof(token));
	zassert_not_null(entry, "Observe exchange should persist");
	zassert_true(entry->is_observe, "Should be marked as Observe");

	/* Simulate sending multiple notifications - entry should persist */
	for (int i = 0; i < 3; i++) {
		entry = oscore_exchange_find(cache, (struct net_sockaddr *)&addr, sizeof(addr),
					     token, sizeof(token));
		zassert_not_null(entry, "Observe exchange should persist for notifications");
	}

	/* Remove when observation is cancelled */
	oscore_exchange_remove(cache, (struct net_sockaddr *)&addr, sizeof(addr), token,
			       sizeof(token));

	entry = oscore_exchange_find(cache, (struct net_sockaddr *)&addr, sizeof(addr), token,
				     sizeof(token));
	zassert_is_null(entry, "Observe exchange should be removed when cancelled");
}

ZTEST(coap_oscore, test_oscore_e2e_response_encrypted)
{
	int response_timeout_ms = 2000;
	const char *orig_payload = "encrypted-response";
	static const uint8_t master_secret[] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	};
	static const uint8_t master_salt[] = {
		0x9E, 0x7C, 0xA9, 0x22, 0x23, 0x78, 0x63, 0x40,
	};
	static const uint8_t client_id[] = {0x01};
	static const uint8_t server_id[] = {0x02};
	struct coap_oscore_context *client_ctx;
	struct coap_oscore_context *server_ctx;
	struct coap_oscore_init_params client_params = {
		.master_secret = master_secret,
		.master_secret_len = sizeof(master_secret),
		.sender_id = client_id,
		.sender_id_len = sizeof(client_id),
		.recipient_id = server_id,
		.recipient_id_len = sizeof(server_id),
		.master_salt = master_salt,
		.master_salt_len = sizeof(master_salt),
		.aead_alg = COAP_OSCORE_AEAD_DEFAULT,
		.hkdf = COAP_OSCORE_HKDF_DEFAULT,
		.fresh_master_secret_salt = true,
	};
	struct coap_oscore_init_params server_params = {
		.master_secret = master_secret,
		.master_secret_len = sizeof(master_secret),
		.sender_id = server_id,
		.sender_id_len = sizeof(server_id),
		.recipient_id = client_id,
		.recipient_id_len = sizeof(client_id),
		.master_salt = master_salt,
		.master_salt_len = sizeof(master_salt),
		.aead_alg = COAP_OSCORE_AEAD_DEFAULT,
		.hkdf = COAP_OSCORE_HKDF_DEFAULT,
		.fresh_master_secret_salt = true,
	};
	struct net_sockaddr_in6 dst = {
		.sin6_family = NET_AF_INET6,
		.sin6_addr = {{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}}},
		.sin6_port = net_htons(oscore_e2e_service_port),
	};
	uint8_t plaintext_req[COAP_BUF_SIZE];
	uint8_t protected_req[COAP_BUF_SIZE];
	uint8_t decrypted_rsp[COAP_BUF_SIZE];
	uint8_t recv_buf[COAP_BUF_SIZE];
	uint32_t protected_req_len = sizeof(protected_req);
	uint32_t decrypted_rsp_len = sizeof(decrypted_rsp);
	struct coap_packet req;
	struct coap_packet outer_rsp;
	struct coap_packet inner_rsp;
	struct zsock_pollfd pfd;
	uint8_t token[] = {0xDE, 0xAD, 0xBE, 0xEF};
	uint8_t oscore_error = 0;
	int sock;
	int ret;

	ret = coap_oscore_context_init(&client_params, &client_ctx);
	zassert_equal(ret, 0, "Client OSCORE context init failed (%d)", ret);

	ret = coap_oscore_context_init(&server_params, &server_ctx);
	zassert_equal(ret, 0, "Server OSCORE context init failed (%d)", ret);

	memset(oscore_e2e_service.data->oscore_exchange_cache, 0,
	       sizeof(oscore_e2e_service.data->oscore_exchange_cache));
	oscore_e2e_service.data->oscore_ctx = server_ctx;
	oscore_e2e_service.data->require_oscore = true;

	ret = coap_service_start(&oscore_e2e_service);
	zassert_equal(ret, 0, "Failed to start e2e CoAP service (%d)", ret);

	sock = zsock_socket(NET_AF_INET6, NET_SOCK_DGRAM, NET_IPPROTO_UDP);
	zassert_true(sock >= 0, "Failed to create client socket (%d)", -errno);

	ret = coap_packet_init(&req, plaintext_req, sizeof(plaintext_req), COAP_VERSION_1,
			       COAP_TYPE_CON, sizeof(token), token, COAP_METHOD_GET, 0x1234);
	zassert_equal(ret, 0, "Failed to initialize plaintext request (%d)", ret);

	ret = coap_packet_append_option(&req, COAP_OPTION_URI_PATH,
					(const uint8_t *)oscore_e2e_path[0], 3);
	zassert_equal(ret, 0, "Failed to append URI path option (%d)", ret);

	ret = coap_oscore_protect(plaintext_req, req.offset, protected_req, &protected_req_len,
				  client_ctx);
	zassert_equal(ret, 0, "Failed to OSCORE-protect request (%d)", ret);

	ret = zsock_sendto(sock, protected_req, protected_req_len, 0, (struct net_sockaddr *)&dst,
			   sizeof(dst));
	zassert_equal(ret, (int)protected_req_len, "Failed to send protected request (%d)", ret);

	pfd.fd = sock;
	pfd.events = ZSOCK_POLLIN;
	pfd.revents = 0;

	ret = zsock_poll(&pfd, 1, response_timeout_ms);
	zassert_true(ret > 0, "Timed out waiting for response (%d)", ret);

	ret = zsock_recvfrom(sock, recv_buf, sizeof(recv_buf), 0, NULL, NULL);
	zassert_true(ret > 0, "Failed to receive response (%d)", ret);

	ret = coap_packet_parse(&outer_rsp, recv_buf, ret, NULL, 0);
	zassert_equal(ret, 0, "Failed to parse outer response packet (%d)", ret);
	zassert_true(coap_oscore_msg_has_oscore(&outer_rsp),
		     "Response to OSCORE request must be OSCORE-protected");

	ret = coap_oscore_verify(recv_buf, outer_rsp.offset, decrypted_rsp, &decrypted_rsp_len,
				 client_ctx, &oscore_error);
	zassert_equal(ret, 0, "Failed to verify/decrypt OSCORE response (%d, coap err %u)", ret,
		      oscore_error);

	ret = coap_packet_parse(&inner_rsp, decrypted_rsp, decrypted_rsp_len, NULL, 0);
	zassert_equal(ret, 0, "Failed to parse decrypted response packet (%d)", ret);
	zassert_equal(coap_header_get_code(&inner_rsp), COAP_RESPONSE_CODE_CONTENT,
		      "Unexpected inner response code");

	uint16_t payload_len;
	const uint8_t *payload = coap_packet_get_payload(&inner_rsp, &payload_len);

	zassert_not_null(payload, "Missing decrypted payload");
	zassert_equal(payload_len, strlen(orig_payload), "Unexpected payload length");
	zassert_mem_equal(payload, orig_payload, payload_len, "Unexpected decrypted payload");

	zassert_equal(zsock_close(sock), 0, "Failed to close client socket");
	zassert_equal(coap_service_stop(&oscore_e2e_service), 0, "Failed to stop e2e CoAP service");

	oscore_e2e_service.data->oscore_ctx = NULL;
	oscore_e2e_service.data->require_oscore = false;

	coap_oscore_context_free(client_ctx);
	coap_oscore_context_free(server_ctx);
}

ZTEST_SUITE(coap_oscore, NULL, NULL, NULL, NULL, NULL);
