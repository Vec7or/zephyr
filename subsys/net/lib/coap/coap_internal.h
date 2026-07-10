/*
 * Copyright (c) 2026 Siemens AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

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
