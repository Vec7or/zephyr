/*
 * Copyright The Zephyr Project Contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(net_coap, CONFIG_COAP_LOG_LEVEL);

#include <errno.h>

#include <zephyr/toolchain.h>
#include <zephyr/net/coap_oscore.h>

#include "coap_edhoc_wrappers.h"

/* Default seam: no EDHOC crypto backend is linked. Integrations override these
 * weak symbols with real uoscore-uedhoc calls.
 */

__weak int coap_edhoc_msg2_gen_wrapper(void *resp_ctx, void *runtime_ctx, const uint8_t *msg1,
				       size_t msg1_len, uint8_t *msg2, size_t *msg2_len,
				       uint8_t *c_r, size_t *c_r_len)
{
	ARG_UNUSED(resp_ctx);
	ARG_UNUSED(runtime_ctx);
	ARG_UNUSED(msg1);
	ARG_UNUSED(msg1_len);
	ARG_UNUSED(msg2);
	ARG_UNUSED(msg2_len);
	ARG_UNUSED(c_r);
	ARG_UNUSED(c_r_len);

	LOG_WRN("EDHOC message_2 generation not available (no EDHOC backend)");
	return -ENOTSUP;
}

__weak int coap_edhoc_msg3_process_wrapper(void *resp_ctx, void *runtime_ctx, const uint8_t *msg3,
					   size_t msg3_len, uint8_t *c_i, size_t *c_i_len,
					   uint8_t *prk_out, size_t *prk_out_len)
{
	ARG_UNUSED(resp_ctx);
	ARG_UNUSED(runtime_ctx);
	ARG_UNUSED(msg3);
	ARG_UNUSED(msg3_len);
	ARG_UNUSED(c_i);
	ARG_UNUSED(c_i_len);
	ARG_UNUSED(prk_out);
	ARG_UNUSED(prk_out_len);

	LOG_WRN("EDHOC message_3 processing not available (no EDHOC backend)");
	return -ENOTSUP;
}

__weak int coap_edhoc_msg4_gen_wrapper(void *resp_ctx, void *runtime_ctx, uint8_t *msg4,
				       size_t *msg4_len, bool *msg4_required)
{
	ARG_UNUSED(resp_ctx);
	ARG_UNUSED(runtime_ctx);
	ARG_UNUSED(msg4);

	/* Most deployments do not use message_4. Default to "not required" so
	 * the handshake can complete without a backend-specific step.
	 */
	if (msg4_len != NULL) {
		*msg4_len = 0U;
	}
	if (msg4_required != NULL) {
		*msg4_required = false;
	}

	return 0;
}

__weak int coap_edhoc_exporter_wrapper(const uint8_t *prk_out, size_t prk_out_len,
				       enum coap_edhoc_export_label label, uint8_t *output,
				       size_t *output_len)
{
	ARG_UNUSED(prk_out);
	ARG_UNUSED(prk_out_len);
	ARG_UNUSED(label);
	ARG_UNUSED(output);
	ARG_UNUSED(output_len);

	LOG_WRN("EDHOC exporter not available (no EDHOC backend)");
	return -ENOTSUP;
}

__weak int coap_oscore_context_init_wrapper(struct coap_oscore_context **ctx,
					    const uint8_t *master_secret,
					    size_t master_secret_len,
					    const uint8_t *master_salt, size_t master_salt_len,
					    const uint8_t *sender_id, size_t sender_id_len,
					    const uint8_t *recipient_id, size_t recipient_id_len)
{
	struct coap_oscore_init_params params = {
		.master_secret = master_secret,
		.master_secret_len = master_secret_len,
		.master_salt = master_salt,
		.master_salt_len = master_salt_len,
		.sender_id = sender_id,
		.sender_id_len = sender_id_len,
		.recipient_id = recipient_id,
		.recipient_id_len = recipient_id_len,
		.aead_alg = COAP_OSCORE_AEAD_AES_CCM_16_64_128,
		.hkdf = COAP_OSCORE_HKDF_SHA_256,
		.fresh_master_secret_salt = true,
	};

	return coap_oscore_context_init(&params, ctx);
}
