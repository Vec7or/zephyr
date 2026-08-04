/*
 * Copyright The Zephyr Project Contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file
 * @brief Cache of EDHOC-derived OSCORE contexts (keyed by C_R / kid).
 */

#ifndef ZEPHYR_SUBSYS_NET_LIB_COAP_COAP_OSCORE_CTX_CACHE_H_
#define ZEPHYR_SUBSYS_NET_LIB_COAP_COAP_OSCORE_CTX_CACHE_H_

#include <stddef.h>
#include <stdint.h>

#include <zephyr/net/coap_service.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Find a cached OSCORE context by kid (C_R).
 *
 * @return Pointer to the matching entry, or NULL if none.
 */
struct coap_oscore_ctx_cache_entry *coap_oscore_ctx_cache_find(
	struct coap_oscore_ctx_cache_entry *cache, size_t cache_size,
	const uint8_t *kid, uint8_t kid_len);

/**
 * @brief Allocate (or reuse) a cache slot for the given kid (C_R).
 *
 * If an entry with the same kid exists it is returned. Otherwise a free slot is
 * used; if the cache is full the oldest entry is evicted (its context, if any,
 * is left untouched for the caller to release).
 *
 * @return Pointer to the entry, or NULL on invalid arguments.
 */
struct coap_oscore_ctx_cache_entry *coap_oscore_ctx_cache_insert(
	struct coap_oscore_ctx_cache_entry *cache, size_t cache_size,
	const uint8_t *kid, uint8_t kid_len);

/**
 * @brief Remove and clear the cache entry matching kid, if any.
 */
void coap_oscore_ctx_cache_remove(struct coap_oscore_ctx_cache_entry *cache, size_t cache_size,
				  const uint8_t *kid, uint8_t kid_len);

/**
 * @brief Evict entries older than @p lifetime_ms relative to @p now.
 *
 * @return Number of entries evicted.
 */
int coap_oscore_ctx_cache_evict_expired(struct coap_oscore_ctx_cache_entry *cache,
					size_t cache_size, int64_t now, int64_t lifetime_ms);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_NET_LIB_COAP_COAP_OSCORE_CTX_CACHE_H_ */
