/*
 * Copyright The Zephyr Project Contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file
 * @brief Device-global EDHOC/OSCORE cache keyed by connection identifier C_R.
 *
 * The EDHOC responder role is device-scoped: a single responder identity and a
 * single C_R namespace are shared by all CoAP services. This cache therefore
 * lives in module-global storage rather than per-service data. A given C_R is
 * only ever in one lifecycle stage at a time, so the in-progress handshake and
 * the resulting OSCORE context share a single entry.
 */

#ifndef ZEPHYR_SUBSYS_NET_LIB_COAP_COAP_EDHOC_CACHE_H_
#define ZEPHYR_SUBSYS_NET_LIB_COAP_COAP_EDHOC_CACHE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct coap_oscore_context;

/** Maximum length of an EDHOC connection identifier (C_R / C_I) tracked here. */
#define COAP_EDHOC_CONN_ID_MAX_LEN 16U

/** Lifecycle stage of a cache entry. */
enum coap_edhoc_cache_state {
	COAP_EDHOC_CACHE_HANDSHAKING, /**< EDHOC handshake in progress */
	COAP_EDHOC_CACHE_COMPLETED,   /**< OSCORE context derived and ready */
};

/**
 * @brief Unified EDHOC/OSCORE cache entry, keyed by connection identifier C_R.
 *
 * While @p state is ::COAP_EDHOC_CACHE_HANDSHAKING only @p handshake is valid.
 * Once ::COAP_EDHOC_CACHE_COMPLETED, @p handshake is released and the derived
 * OSCORE keying material and @p ctx are valid. coap_oscore_context_init() keeps
 * referencing the keying-material buffers for the lifetime of @p ctx.
 */
struct coap_edhoc_cache_entry {
	uint8_t c_r[COAP_EDHOC_CONN_ID_MAX_LEN]; /**< Connection identifier C_R / kid */
	uint8_t c_r_len;                         /**< Length of @p c_r */
	enum coap_edhoc_cache_state state;       /**< Lifecycle stage */
	void *handshake;                         /**< Opaque EDHOC handshake state */
	uint8_t sender_id[COAP_EDHOC_CONN_ID_MAX_LEN]; /**< Sender ID / C_I */
	uint8_t sender_id_len;                   /**< Length of @p sender_id */
	uint8_t master_secret[32];               /**< Derived OSCORE Master Secret */
	size_t master_secret_len;                /**< Length of @p master_secret */
	uint8_t master_salt[16];                 /**< Derived OSCORE Master Salt */
	size_t master_salt_len;                  /**< Length of @p master_salt */
	struct coap_oscore_context *ctx;         /**< Derived OSCORE context */
	int64_t timestamp;                       /**< Stage entry timestamp */
	bool active;                             /**< True if the entry is in use */
};

/**
 * @brief Find an active cache entry by connection identifier C_R.
 *
 * @return Pointer to the matching entry, or NULL if none.
 */
struct coap_edhoc_cache_entry *coap_edhoc_cache_find(const uint8_t *c_r, uint8_t c_r_len);

/**
 * @brief Allocate (or reuse) a handshaking cache entry for C_R.
 *
 * If an entry with the same C_R exists it is returned. Otherwise a free slot is
 * used; if the cache is full the oldest entry is evicted.
 *
 * @return Pointer to the entry, or NULL on invalid arguments.
 */
struct coap_edhoc_cache_entry *coap_edhoc_cache_insert(const uint8_t *c_r, uint8_t c_r_len);

/**
 * @brief Remove and clear the cache entry matching C_R, if any.
 */
void coap_edhoc_cache_remove(const uint8_t *c_r, uint8_t c_r_len);

/**
 * @brief Evict expired entries, applying the lifetime for each entry's stage.
 *
 * Handshaking entries use CONFIG_COAP_EDHOC_SESSION_LIFETIME_MS; completed
 * entries use CONFIG_COAP_OSCORE_CTX_LIFETIME_MS.
 *
 * @return Number of entries evicted.
 */
int coap_edhoc_cache_evict_expired(int64_t now);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_NET_LIB_COAP_COAP_EDHOC_CACHE_H_ */
