/*
 * Copyright The Zephyr Project Contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(net_coap, CONFIG_COAP_LOG_LEVEL);

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>

#include "coap_edhoc.h"
#include "coap_edhoc_combined_blockwise.h"

#define OUTER_BLOCK_CACHE_SIZE CONFIG_COAP_EDHOC_COMBINED_OUTER_BLOCK_CACHE_SIZE

/* Response buffer for 2.31 Continue / error responses, used under the server lock. */
static uint8_t outer_block_resp_buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];

static bool addr_matches(const struct coap_edhoc_outer_block_entry *entry,
			 const struct net_sockaddr *addr, net_socklen_t addr_len)
{
	return entry->addr_len == addr_len &&
	       memcmp(&entry->addr, addr, addr_len) == 0;
}

/* Serialize all Request-Tag options as [len][bytes]... (RFC 9175 Section 3.2). */
static int parse_request_tag_list(const struct coap_packet *request, uint8_t *count,
				  uint8_t *data, size_t data_size, size_t *data_len)
{
	struct coap_option opts[8];
	int n;
	size_t off = 0U;

	*count = 0U;
	*data_len = 0U;

	n = coap_find_options(request, COAP_OPTION_REQUEST_TAG, opts, ARRAY_SIZE(opts));
	if (n < 0) {
		return -EINVAL;
	}
	if (n == 0) {
		return 0;
	}

	for (int i = 0; i < n; i++) {
		if (opts[i].len > 8U) {
			return -EINVAL;
		}
		if ((off + 1U + opts[i].len) > data_size) {
			return -ENOMEM;
		}
		data[off++] = (uint8_t)opts[i].len;
		memcpy(&data[off], opts[i].value, opts[i].len);
		off += opts[i].len;
	}

	*count = (uint8_t)n;
	*data_len = off;

	return 0;
}

static bool request_tag_lists_equal(const struct coap_edhoc_outer_block_entry *entry,
				    uint8_t count, const uint8_t *data, size_t data_len)
{
	return entry->request_tag_count == count && entry->request_tag_data_len == data_len &&
	       memcmp(entry->request_tag_data, data, data_len) == 0;
}

static struct coap_edhoc_outer_block_entry *
outer_block_find(struct coap_edhoc_outer_block_entry *cache, const struct net_sockaddr *addr,
		 net_socklen_t addr_len, const uint8_t *token, uint8_t tkl, uint8_t rt_count,
		 const uint8_t *rt_data, size_t rt_len)
{
	for (size_t i = 0; i < OUTER_BLOCK_CACHE_SIZE; i++) {
		struct coap_edhoc_outer_block_entry *e = &cache[i];

		if (e->active && e->tkl == tkl && memcmp(e->token, token, tkl) == 0 &&
		    addr_matches(e, addr, addr_len) &&
		    request_tag_lists_equal(e, rt_count, rt_data, rt_len)) {
			return e;
		}
	}

	return NULL;
}

static struct coap_edhoc_outer_block_entry *
outer_block_alloc(struct coap_edhoc_outer_block_entry *cache, int64_t now)
{
	struct coap_edhoc_outer_block_entry *slot = NULL;
	struct coap_edhoc_outer_block_entry *oldest = NULL;

	for (size_t i = 0; i < OUTER_BLOCK_CACHE_SIZE; i++) {
		struct coap_edhoc_outer_block_entry *e = &cache[i];

		if (!e->active) {
			if (slot == NULL) {
				slot = e;
			}
		} else if (oldest == NULL || e->timestamp < oldest->timestamp) {
			oldest = e;
		}
	}

	if (slot == NULL) {
		slot = oldest;
	}
	if (slot != NULL) {
		memset(slot, 0, sizeof(*slot));
		slot->timestamp = now;
	}

	return slot;
}

static int send_simple_response(const struct coap_service *service,
				const struct coap_packet *request, uint8_t code, int block_val,
				const struct net_sockaddr *addr, net_socklen_t addr_len)
{
	struct coap_packet response;
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint8_t tkl = coap_header_get_token(request, token);
	uint16_t id = coap_header_get_id(request);
	uint8_t type = (coap_header_get_type(request) == COAP_TYPE_CON) ? COAP_TYPE_ACK
								       : COAP_TYPE_NON_CON;
	int ret;

	ret = coap_packet_init(&response, outer_block_resp_buf, sizeof(outer_block_resp_buf),
			       COAP_VERSION_1, type, tkl, token, code, id);
	if (ret < 0) {
		return ret;
	}

	if (block_val >= 0) {
		ret = coap_append_option_int(&response, COAP_OPTION_BLOCK1, (unsigned int)block_val);
		if (ret < 0) {
			return ret;
		}
	}

	return coap_service_send(service, &response, addr, addr_len, NULL);
}

static int reconstruct(struct coap_edhoc_outer_block_entry *entry, uint8_t *out_buf,
		       size_t out_size, size_t *out_len)
{
	size_t total = entry->header_template_len + 1U + entry->accumulated_len;

	if (total > out_size) {
		return -ENOMEM;
	}

	memcpy(out_buf, entry->header_template, entry->header_template_len);
	out_buf[entry->header_template_len] = 0xFFU; /* CoAP payload marker */
	memcpy(out_buf + entry->header_template_len + 1U, entry->reassembly_buf,
	       entry->accumulated_len);
	*out_len = total;

	return 0;
}

int coap_edhoc_outer_block_process(const struct coap_service *service, struct coap_packet *request,
				   const uint8_t *in_buf, size_t in_len,
				   const struct net_sockaddr *addr, net_socklen_t addr_len,
				   uint8_t *out_buf, size_t out_size, size_t *out_len)
{
	struct coap_edhoc_outer_block_entry *cache = service->data->edhoc_outer_block_cache;
	struct coap_edhoc_outer_block_entry *entry;
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint8_t tkl;
	uint8_t rt_count = 0U;
	uint8_t rt_data[64];
	size_t rt_len = 0U;
	const uint8_t *payload;
	uint16_t payload_len;
	int block_val;
	uint32_t num;
	bool more;
	uint16_t block_bytes;
	int64_t now = k_uptime_get();
	int ret;

	ARG_UNUSED(in_buf);
	ARG_UNUSED(in_len);

	block_val = coap_get_option_int(request, COAP_OPTION_BLOCK1);
	if (block_val < 0) {
		/* No outer Block1: single-message combined request or non-block. */
		return COAP_EDHOC_OUTER_BLOCK_PASS;
	}

	num = GET_BLOCK_NUM(block_val);
	more = GET_MORE(block_val);
	block_bytes = coap_block_size_to_bytes(GET_BLOCK_SIZE(block_val));

	tkl = coap_header_get_token(request, token);
	if (tkl == 0U) {
		/* RFC 7959: block-wise requests require a token. */
		(void)send_simple_response(service, request, COAP_RESPONSE_CODE_BAD_REQUEST, -1,
					   addr, addr_len);
		return COAP_EDHOC_OUTER_BLOCK_ERROR;
	}

	ret = parse_request_tag_list(request, &rt_count, rt_data, sizeof(rt_data), &rt_len);
	if (ret < 0) {
		(void)send_simple_response(service, request, COAP_RESPONSE_CODE_BAD_REQUEST, -1,
					   addr, addr_len);
		return COAP_EDHOC_OUTER_BLOCK_ERROR;
	}

	payload = coap_packet_get_payload(request, &payload_len);

	if (num == 0U) {
		size_t header_len;

		/* First block must carry the EDHOC option to be a combined request. */
		if (!coap_edhoc_msg_has_edhoc(request)) {
			return COAP_EDHOC_OUTER_BLOCK_PASS;
		}

		if (payload == NULL || payload_len == 0U) {
			(void)send_simple_response(service, request,
						   COAP_RESPONSE_CODE_BAD_REQUEST, -1, addr,
						   addr_len);
			return COAP_EDHOC_OUTER_BLOCK_ERROR;
		}

		entry = outer_block_alloc(cache, now);
		if (entry == NULL) {
			(void)send_simple_response(service, request,
						   COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE, -1, addr,
						   addr_len);
			return COAP_EDHOC_OUTER_BLOCK_ERROR;
		}

		/* Header template is everything before the payload marker. */
		header_len = (size_t)(payload - request->data) - 1U;
		if (header_len > sizeof(entry->header_template) ||
		    payload_len > sizeof(entry->reassembly_buf)) {
			memset(entry, 0, sizeof(*entry));
			(void)send_simple_response(service, request,
						   COAP_RESPONSE_CODE_REQUEST_TOO_LARGE, -1, addr,
						   addr_len);
			return COAP_EDHOC_OUTER_BLOCK_ERROR;
		}

		memcpy(&entry->addr, addr, addr_len);
		entry->addr_len = addr_len;
		memcpy(entry->token, token, tkl);
		entry->tkl = tkl;
		entry->request_tag_count = rt_count;
		memcpy(entry->request_tag_data, rt_data, rt_len);
		entry->request_tag_data_len = rt_len;
		entry->block_ctx.block_size = GET_BLOCK_SIZE(block_val);
		memcpy(entry->header_template, request->data, header_len);
		entry->header_template_len = header_len;
		memcpy(entry->reassembly_buf, payload, payload_len);
		entry->accumulated_len = payload_len;
		entry->active = true;

		if (!more) {
			ret = reconstruct(entry, out_buf, out_size, out_len);
			memset(entry, 0, sizeof(*entry));
			if (ret < 0) {
				return COAP_EDHOC_OUTER_BLOCK_ERROR;
			}
			return COAP_EDHOC_OUTER_BLOCK_COMPLETE;
		}

		ret = send_simple_response(service, request, COAP_RESPONSE_CODE_CONTINUE, block_val,
					   addr, addr_len);
		if (ret < 0) {
			memset(entry, 0, sizeof(*entry));
			return COAP_EDHOC_OUTER_BLOCK_ERROR;
		}

		return COAP_EDHOC_OUTER_BLOCK_WAITING;
	}

	/* Continuation block. */
	entry = outer_block_find(cache, addr, addr_len, token, tkl, rt_count, rt_data, rt_len);
	if (entry == NULL) {
		(void)send_simple_response(service, request, COAP_RESPONSE_CODE_INCOMPLETE, -1, addr,
					   addr_len);
		return COAP_EDHOC_OUTER_BLOCK_ERROR;
	}

	/* Validate block size consistency and ordering (RFC 7959). */
	if (GET_BLOCK_SIZE(block_val) != entry->block_ctx.block_size ||
	    (num * block_bytes) != entry->accumulated_len) {
		memset(entry, 0, sizeof(*entry));
		(void)send_simple_response(service, request, COAP_RESPONSE_CODE_INCOMPLETE, -1, addr,
					   addr_len);
		return COAP_EDHOC_OUTER_BLOCK_ERROR;
	}

	if (payload == NULL || payload_len == 0U) {
		memset(entry, 0, sizeof(*entry));
		(void)send_simple_response(service, request, COAP_RESPONSE_CODE_BAD_REQUEST, -1,
					   addr, addr_len);
		return COAP_EDHOC_OUTER_BLOCK_ERROR;
	}

	if ((entry->accumulated_len + payload_len) > sizeof(entry->reassembly_buf)) {
		memset(entry, 0, sizeof(*entry));
		(void)send_simple_response(service, request, COAP_RESPONSE_CODE_REQUEST_TOO_LARGE,
					   -1, addr, addr_len);
		return COAP_EDHOC_OUTER_BLOCK_ERROR;
	}

	memcpy(entry->reassembly_buf + entry->accumulated_len, payload, payload_len);
	entry->accumulated_len += payload_len;
	entry->timestamp = now;

	if (!more) {
		ret = reconstruct(entry, out_buf, out_size, out_len);
		memset(entry, 0, sizeof(*entry));
		if (ret < 0) {
			return COAP_EDHOC_OUTER_BLOCK_ERROR;
		}
		return COAP_EDHOC_OUTER_BLOCK_COMPLETE;
	}

	ret = send_simple_response(service, request, COAP_RESPONSE_CODE_CONTINUE, block_val, addr,
				   addr_len);
	if (ret < 0) {
		memset(entry, 0, sizeof(*entry));
		return COAP_EDHOC_OUTER_BLOCK_ERROR;
	}

	return COAP_EDHOC_OUTER_BLOCK_WAITING;
}
