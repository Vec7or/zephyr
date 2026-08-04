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

#include "coap_edhoc_session.h"

static bool c_r_matches(const struct coap_edhoc_session *entry, const uint8_t *c_r,
			uint8_t c_r_len)
{
	return entry->active && entry->c_r_len == c_r_len &&
	       memcmp(entry->c_r, c_r, c_r_len) == 0;
}

struct coap_edhoc_session *coap_edhoc_session_find(struct coap_edhoc_session *cache,
						   size_t cache_size,
						   const uint8_t *c_r, uint8_t c_r_len)
{
	if (cache == NULL || c_r == NULL || c_r_len > COAP_EDHOC_CONN_ID_MAX_LEN) {
		return NULL;
	}

	for (size_t i = 0; i < cache_size; i++) {
		if (c_r_matches(&cache[i], c_r, c_r_len)) {
			return &cache[i];
		}
	}

	return NULL;
}

struct coap_edhoc_session *coap_edhoc_session_insert(struct coap_edhoc_session *cache,
						     size_t cache_size,
						     const uint8_t *c_r, uint8_t c_r_len)
{
	struct coap_edhoc_session *slot = NULL;
	struct coap_edhoc_session *oldest = NULL;

	if (cache == NULL || c_r == NULL || c_r_len > COAP_EDHOC_CONN_ID_MAX_LEN) {
		return NULL;
	}

	for (size_t i = 0; i < cache_size; i++) {
		if (c_r_matches(&cache[i], c_r, c_r_len)) {
			return &cache[i];
		}

		if (!cache[i].active) {
			if (slot == NULL) {
				slot = &cache[i];
			}
		} else if (oldest == NULL || cache[i].timestamp < oldest->timestamp) {
			oldest = &cache[i];
		}
	}

	if (slot == NULL) {
		/* Cache full: evict the oldest entry. */
		slot = oldest;
	}

	if (slot == NULL) {
		return NULL;
	}

	memset(slot, 0, sizeof(*slot));
	memcpy(slot->c_r, c_r, c_r_len);
	slot->c_r_len = c_r_len;
	slot->timestamp = k_uptime_get();
	slot->active = true;

	return slot;
}

void coap_edhoc_session_remove(struct coap_edhoc_session *cache, size_t cache_size,
			       const uint8_t *c_r, uint8_t c_r_len)
{
	struct coap_edhoc_session *entry;

	entry = coap_edhoc_session_find(cache, cache_size, c_r, c_r_len);
	if (entry != NULL) {
		memset(entry, 0, sizeof(*entry));
	}
}

int coap_edhoc_session_evict_expired(struct coap_edhoc_session *cache, size_t cache_size,
				     int64_t now, int64_t lifetime_ms)
{
	int evicted = 0;

	if (cache == NULL) {
		return -EINVAL;
	}

	for (size_t i = 0; i < cache_size; i++) {
		if (cache[i].active && (now - cache[i].timestamp) >= lifetime_ms) {
			memset(&cache[i], 0, sizeof(cache[i]));
			evicted++;
		}
	}

	return evicted;
}
