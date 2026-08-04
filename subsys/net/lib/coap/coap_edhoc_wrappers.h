/*
 * Copyright The Zephyr Project Contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file
 * @brief EDHOC integration seam for the CoAP server.
 *
 * These wrappers isolate the CoAP server from the concrete EDHOC
 * implementation (uoscore-uedhoc). They are defined as weak symbols returning
 * -ENOTSUP so that the CoAP-level plumbing builds and can be exercised without
 * a crypto backend; an integration provides real implementations by defining
 * strong symbols with the same signatures.
 */

#ifndef ZEPHYR_SUBSYS_NET_LIB_COAP_COAP_EDHOC_WRAPPERS_H_
#define ZEPHYR_SUBSYS_NET_LIB_COAP_COAP_EDHOC_WRAPPERS_H_

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include <zephyr/net/coap_oscore.h>

#ifdef __cplusplus
extern "C" {
#endif

/** EDHOC-Exporter labels for OSCORE key material (RFC 9528 Appendix A.1). */
enum coap_edhoc_export_label {
	COAP_EDHOC_EXPORT_OSCORE_MASTER_SECRET = 0,
	COAP_EDHOC_EXPORT_OSCORE_MASTER_SALT = 1,
};

/**
 * @brief Process EDHOC message_1 and generate message_2 (RFC 9528 A.2.1).
 *
 * @param resp_ctx    Opaque EDHOC responder context.
 * @param runtime_ctx Opaque EDHOC runtime context.
 * @param msg1        Received message_1 bytes.
 * @param msg1_len    Length of @p msg1.
 * @param msg2        Output buffer for message_2.
 * @param msg2_len    In: capacity. Out: length written.
 * @param c_r         Output buffer for the selected connection identifier C_R.
 * @param c_r_len     In: capacity. Out: length written.
 *
 * @return 0 on success, negative errno on failure (-ENOTSUP if no backend).
 */
int coap_edhoc_msg2_gen_wrapper(void *resp_ctx, void *runtime_ctx, const uint8_t *msg1,
				size_t msg1_len, uint8_t *msg2, size_t *msg2_len, uint8_t *c_r,
				size_t *c_r_len);

/**
 * @brief Process EDHOC message_3 (RFC 9528 Section 5.4.3).
 *
 * @param resp_ctx    Opaque EDHOC responder context.
 * @param runtime_ctx Opaque EDHOC runtime context.
 * @param msg3        Received message_3 bytes.
 * @param msg3_len    Length of @p msg3.
 * @param c_i         Output buffer for the initiator connection identifier C_I.
 * @param c_i_len     In: capacity. Out: length written.
 * @param prk_out     Output buffer for PRK_out.
 * @param prk_out_len In: capacity. Out: length written.
 *
 * @return 0 on success, negative errno on failure (-ENOTSUP if no backend).
 */
int coap_edhoc_msg3_process_wrapper(void *resp_ctx, void *runtime_ctx, const uint8_t *msg3,
				    size_t msg3_len, uint8_t *c_i, size_t *c_i_len,
				    uint8_t *prk_out, size_t *prk_out_len);

/**
 * @brief Generate EDHOC message_4 if the application requires it.
 *
 * @param resp_ctx     Opaque EDHOC responder context.
 * @param runtime_ctx  Opaque EDHOC runtime context.
 * @param msg4         Output buffer for message_4.
 * @param msg4_len     In: capacity. Out: length written (0 if not required).
 * @param msg4_required Out: true if message_4 was produced and must be sent.
 *
 * @return 0 on success, negative errno on failure (-ENOTSUP if no backend).
 */
int coap_edhoc_msg4_gen_wrapper(void *resp_ctx, void *runtime_ctx, uint8_t *msg4,
				size_t *msg4_len, bool *msg4_required);

/**
 * @brief Derive OSCORE keying material from PRK_out (RFC 9528 Appendix A.1).
 *
 * @param prk_out     PRK_out from a completed EDHOC exchange.
 * @param prk_out_len Length of @p prk_out.
 * @param label       Which key material to export.
 * @param output      Output buffer.
 * @param output_len  In: capacity. Out: length written.
 *
 * @return 0 on success, negative errno on failure (-ENOTSUP if no backend).
 */
int coap_edhoc_exporter_wrapper(const uint8_t *prk_out, size_t prk_out_len,
				enum coap_edhoc_export_label label, uint8_t *output,
				size_t *output_len);

/**
 * @brief Initialize an OSCORE context from EDHOC-derived key material.
 *
 * Per RFC 9528 Appendix A.1 the responder uses Sender ID = C_I and
 * Recipient ID = C_R. The referenced @p master_secret, @p master_salt and
 * @p sender_id buffers must remain valid for the lifetime of @p ctx.
 *
 * @param ctx               Out: created OSCORE context handle.
 * @param master_secret     OSCORE Master Secret.
 * @param master_secret_len Length of @p master_secret.
 * @param master_salt       OSCORE Master Salt (may be NULL).
 * @param master_salt_len   Length of @p master_salt.
 * @param sender_id         Sender ID (C_I).
 * @param sender_id_len     Length of @p sender_id.
 * @param recipient_id      Recipient ID (C_R).
 * @param recipient_id_len  Length of @p recipient_id.
 *
 * @return 0 on success, negative errno on failure.
 */
int coap_oscore_context_init_wrapper(struct coap_oscore_context **ctx,
				     const uint8_t *master_secret, size_t master_secret_len,
				     const uint8_t *master_salt, size_t master_salt_len,
				     const uint8_t *sender_id, size_t sender_id_len,
				     const uint8_t *recipient_id, size_t recipient_id_len);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_NET_LIB_COAP_COAP_EDHOC_WRAPPERS_H_ */
