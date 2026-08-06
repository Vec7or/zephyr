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

#include "coap_edhoc_cache.h"

/* Device-global cache: EDHOC is a single-responder, device-scoped role and C_R
 * is chosen locally, so one global C_R namespace is shared by all services.
 */
static struct coap_edhoc_cache_entry edhoc_cache[CONFIG_COAP_EDHOC_CACHE_SIZE];
static K_MUTEX_DEFINE(edhoc_cache_lock);

static bool c_r_matches(const struct coap_edhoc_cache_entry *entry, const uint8_t *c_r,
			uint8_t c_r_len)
{
	return entry->active && entry->c_r_len == c_r_len &&
	       memcmp(entry->c_r, c_r, c_r_len) == 0;
}

struct coap_edhoc_cache_entry *coap_edhoc_cache_find(const uint8_t *c_r, uint8_t c_r_len)
{
	struct coap_edhoc_cache_entry *match = NULL;

	if (c_r == NULL || c_r_len > COAP_EDHOC_CONN_ID_MAX_LEN) {
		return NULL;
	}

	k_mutex_lock(&edhoc_cache_lock, K_FOREVER);
	for (size_t i = 0; i < ARRAY_SIZE(edhoc_cache); i++) {
		if (c_r_matches(&edhoc_cache[i], c_r, c_r_len)) {
			match = &edhoc_cache[i];
			break;
		}
	}
	k_mutex_unlock(&edhoc_cache_lock);

	return match;
}

struct coap_edhoc_cache_entry *coap_edhoc_cache_insert(const uint8_t *c_r, uint8_t c_r_len)
{
	struct coap_edhoc_cache_entry *slot = NULL;
	struct coap_edhoc_cache_entry *oldest = NULL;

	if (c_r == NULL || c_r_len > COAP_EDHOC_CONN_ID_MAX_LEN) {
		return NULL;
	}

	k_mutex_lock(&edhoc_cache_lock, K_FOREVER);
	for (size_t i = 0; i < ARRAY_SIZE(edhoc_cache); i++) {
		if (c_r_matches(&edhoc_cache[i], c_r, c_r_len)) {
			k_mutex_unlock(&edhoc_cache_lock);
			return &edhoc_cache[i];
		}

		if (!edhoc_cache[i].active) {
			if (slot == NULL) {
				slot = &edhoc_cache[i];
			}
		} else if (oldest == NULL || edhoc_cache[i].timestamp < oldest->timestamp) {
			oldest = &edhoc_cache[i];
		}
	}

	if (slot == NULL) {
		/* Cache full: evict the oldest entry. */
		slot = oldest;
	}

	if (slot == NULL) {
		k_mutex_unlock(&edhoc_cache_lock);
		return NULL;
	}

	memset(slot, 0, sizeof(*slot));
	memcpy(slot->c_r, c_r, c_r_len);
	slot->c_r_len = c_r_len;
	slot->state = COAP_EDHOC_CACHE_HANDSHAKING;
	slot->timestamp = k_uptime_get();
	slot->active = true;
	k_mutex_unlock(&edhoc_cache_lock);

	return slot;
}

void coap_edhoc_cache_remove(const uint8_t *c_r, uint8_t c_r_len)
{
	if (c_r == NULL || c_r_len > COAP_EDHOC_CONN_ID_MAX_LEN) {
		return;
	}

	k_mutex_lock(&edhoc_cache_lock, K_FOREVER);
	for (size_t i = 0; i < ARRAY_SIZE(edhoc_cache); i++) {
		if (c_r_matches(&edhoc_cache[i], c_r, c_r_len)) {
			memset(&edhoc_cache[i], 0, sizeof(edhoc_cache[i]));
			break;
		}
	}
	k_mutex_unlock(&edhoc_cache_lock);
}

int coap_edhoc_cache_evict_expired(int64_t now)
{
	int evicted = 0;

	k_mutex_lock(&edhoc_cache_lock, K_FOREVER);
	for (size_t i = 0; i < ARRAY_SIZE(edhoc_cache); i++) {
		int64_t lifetime_ms;

		if (!edhoc_cache[i].active) {
			continue;
		}

		lifetime_ms = (edhoc_cache[i].state == COAP_EDHOC_CACHE_COMPLETED)
				      ? CONFIG_COAP_OSCORE_CTX_LIFETIME_MS
				      : CONFIG_COAP_EDHOC_SESSION_LIFETIME_MS;

		if ((now - edhoc_cache[i].timestamp) >= lifetime_ms) {
			memset(&edhoc_cache[i], 0, sizeof(edhoc_cache[i]));
			evicted++;
		}
	}
	k_mutex_unlock(&edhoc_cache_lock);

	return evicted;
}
