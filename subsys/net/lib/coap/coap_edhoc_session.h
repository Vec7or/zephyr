/*
 * Copyright The Zephyr Project Contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file
 * @brief EDHOC session cache management (keyed by C_R).
 */

#ifndef ZEPHYR_SUBSYS_NET_LIB_COAP_COAP_EDHOC_SESSION_H_
#define ZEPHYR_SUBSYS_NET_LIB_COAP_COAP_EDHOC_SESSION_H_

#include <stddef.h>
#include <stdint.h>

#include <zephyr/net/coap_service.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Find an active EDHOC session by connection identifier C_R.
 *
 * @return Pointer to the matching session, or NULL if none.
 */
struct coap_edhoc_session *coap_edhoc_session_find(struct coap_edhoc_session *cache,
						   size_t cache_size,
						   const uint8_t *c_r, uint8_t c_r_len);

/**
 * @brief Allocate (or reuse) an EDHOC session slot for C_R.
 *
 * If a session with the same C_R exists it is returned. Otherwise a free slot
 * is used; if the cache is full the oldest entry is evicted.
 *
 * @return Pointer to the session slot, or NULL on invalid arguments.
 */
struct coap_edhoc_session *coap_edhoc_session_insert(struct coap_edhoc_session *cache,
						     size_t cache_size,
						     const uint8_t *c_r, uint8_t c_r_len);

/**
 * @brief Remove and clear the EDHOC session matching C_R, if any.
 */
void coap_edhoc_session_remove(struct coap_edhoc_session *cache, size_t cache_size,
			       const uint8_t *c_r, uint8_t c_r_len);

/**
 * @brief Evict sessions older than @p lifetime_ms relative to @p now.
 *
 * @return Number of sessions evicted.
 */
int coap_edhoc_session_evict_expired(struct coap_edhoc_session *cache, size_t cache_size,
				     int64_t now, int64_t lifetime_ms);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_NET_LIB_COAP_COAP_EDHOC_SESSION_H_ */
