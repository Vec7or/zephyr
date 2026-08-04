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

#include "coap_oscore_ctx_cache.h"

static bool kid_matches(const struct coap_oscore_ctx_cache_entry *entry, const uint8_t *kid,
			uint8_t kid_len)
{
	return entry->active && entry->kid_len == kid_len &&
	       memcmp(entry->kid, kid, kid_len) == 0;
}

struct coap_oscore_ctx_cache_entry *coap_oscore_ctx_cache_find(
	struct coap_oscore_ctx_cache_entry *cache, size_t cache_size,
	const uint8_t *kid, uint8_t kid_len)
{
	if (cache == NULL || kid == NULL || kid_len > COAP_EDHOC_CONN_ID_MAX_LEN) {
		return NULL;
	}

	for (size_t i = 0; i < cache_size; i++) {
		if (kid_matches(&cache[i], kid, kid_len)) {
			return &cache[i];
		}
	}

	return NULL;
}

struct coap_oscore_ctx_cache_entry *coap_oscore_ctx_cache_insert(
	struct coap_oscore_ctx_cache_entry *cache, size_t cache_size,
	const uint8_t *kid, uint8_t kid_len)
{
	struct coap_oscore_ctx_cache_entry *slot = NULL;
	struct coap_oscore_ctx_cache_entry *oldest = NULL;

	if (cache == NULL || kid == NULL || kid_len > COAP_EDHOC_CONN_ID_MAX_LEN) {
		return NULL;
	}

	for (size_t i = 0; i < cache_size; i++) {
		if (kid_matches(&cache[i], kid, kid_len)) {
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
		slot = oldest;
	}

	if (slot == NULL) {
		return NULL;
	}

	memset(slot, 0, sizeof(*slot));
	memcpy(slot->kid, kid, kid_len);
	slot->kid_len = kid_len;
	slot->timestamp = k_uptime_get();
	slot->active = true;

	return slot;
}

void coap_oscore_ctx_cache_remove(struct coap_oscore_ctx_cache_entry *cache, size_t cache_size,
				  const uint8_t *kid, uint8_t kid_len)
{
	struct coap_oscore_ctx_cache_entry *entry;

	entry = coap_oscore_ctx_cache_find(cache, cache_size, kid, kid_len);
	if (entry != NULL) {
		memset(entry, 0, sizeof(*entry));
	}
}

int coap_oscore_ctx_cache_evict_expired(struct coap_oscore_ctx_cache_entry *cache,
					size_t cache_size, int64_t now, int64_t lifetime_ms)
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
