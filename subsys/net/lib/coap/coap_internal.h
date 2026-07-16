/*
 * Copyright (c) 2026 Siemens AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_SUBSYS_NET_LIB_COAP_INTERNAL_H_
#define ZEPHYR_SUBSYS_NET_LIB_COAP_INTERNAL_H_

#include <stdbool.h>

#include <zephyr/net/net_ip.h>

/** @file
 * @brief CoAP Internal helpers
 * Internal helpers for the CoAP subsystem.
 */

/**
 * @brief Compare two network socket addresses for equality
 *
 * @param a net_sockaddr to compare
 * @param b net_sockaddr to compare
 * @return true if the two addresses are equal, false otherwise
 */
bool coap_sockaddr_equal(const struct net_sockaddr *a, const struct net_sockaddr *b);

#endif /* ZEPHYR_SUBSYS_NET_LIB_COAP_INTERNAL_H_ */
