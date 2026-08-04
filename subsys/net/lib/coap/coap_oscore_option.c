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

#include "coap_oscore_option.h"

int coap_oscore_option_extract_kid(const struct coap_packet *cpkt,
				   uint8_t *kid, size_t *kid_len)
{
	struct coap_option option;
	const uint8_t *value;
	size_t value_len;
	size_t max_kid_len;
	size_t pos = 0U;
	size_t kid_on_wire;
	uint8_t flags;
	uint8_t n;
	bool k;
	bool h;
	int ret;

	if (cpkt == NULL || kid == NULL || kid_len == NULL) {
		return -EINVAL;
	}

	max_kid_len = *kid_len;

	ret = coap_find_options(cpkt, COAP_OPTION_OSCORE, &option, 1);
	if (ret <= 0) {
		return -ENOENT;
	}

	value = option.value;
	value_len = option.len;

	/* RFC 8613 Section 6.1: a zero-length option value carries no kid. */
	if (value_len == 0U) {
		return -ENOENT;
	}

	/* Flag byte: bits 0-2 = n (Partial IV length), bit 3 = k (kid present),
	 * bit 4 = h (kid context present), bits 5-7 reserved (must be zero).
	 */
	flags = value[pos++];
	n = flags & 0x07U;
	k = (flags & 0x08U) != 0U;
	h = (flags & 0x10U) != 0U;

	if ((flags & 0xE0U) != 0U) {
		LOG_ERR("OSCORE option has reserved bits set (0x%02x)", flags);
		return -EINVAL;
	}

	if (n == 6U || n == 7U) {
		LOG_ERR("OSCORE option has reserved Partial IV length (%u)", n);
		return -EINVAL;
	}

	/* Skip the Partial IV: exactly n raw bytes (not length-prefixed). */
	if ((pos + n) > value_len) {
		LOG_ERR("OSCORE option too short for Partial IV");
		return -EINVAL;
	}
	pos += n;

	/* Skip the kid context: 1-byte length s followed by s bytes. */
	if (h) {
		uint8_t s;

		if (pos >= value_len) {
			LOG_ERR("OSCORE option truncated at kid context length");
			return -EINVAL;
		}
		s = value[pos++];
		if ((pos + s) > value_len) {
			LOG_ERR("OSCORE option kid context length invalid");
			return -EINVAL;
		}
		pos += s;
	}

	if (!k) {
		return -ENOENT;
	}

	/* RFC 8613 Section 6.1: the kid is the remaining bytes (not prefixed). */
	kid_on_wire = value_len - pos;
	if (kid_on_wire > max_kid_len) {
		LOG_ERR("OSCORE kid too large (%zu > %zu)", kid_on_wire, max_kid_len);
		return -ENOMEM;
	}

	memcpy(kid, &value[pos], kid_on_wire);
	*kid_len = kid_on_wire;

	return 0;
}
