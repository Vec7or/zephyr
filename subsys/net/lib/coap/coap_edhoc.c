/*
 * Copyright The Zephyr Project Contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(net_coap, CONFIG_COAP_LOG_LEVEL);

#include <errno.h>
#include <string.h>

#include <zephyr/net/coap.h>

#include "coap_edhoc.h"

bool coap_edhoc_msg_has_edhoc(const struct coap_packet *cpkt)
{
	struct coap_option option;
	int ret;

	if (cpkt == NULL) {
		return false;
	}

	ret = coap_find_options(cpkt, COAP_OPTION_EDHOC, &option, 1);
	return ret > 0;
}

int coap_edhoc_validate_option(const struct coap_packet *cpkt, bool *present)
{
	struct coap_option option[2];
	int ret;

	if (cpkt == NULL || present == NULL) {
		return -EINVAL;
	}

	/* RFC 9668 Section 3.1: EDHOC option MUST occur at most once. Its value
	 * is ignored, so only the count matters here.
	 */
	ret = coap_find_options(cpkt, COAP_OPTION_EDHOC, option, 2);
	*present = ret >= 1;

	if (ret > 1) {
		LOG_ERR("Multiple EDHOC options present, violates RFC 9668 Section 3.1");
		return -EBADMSG;
	}

	return 0;
}

int coap_edhoc_split_comb_payload(const uint8_t *payload, size_t payload_len,
				  struct coap_edhoc_span *edhoc_msg3,
				  struct coap_edhoc_span *oscore_payload)
{
	uint8_t initial_byte;
	uint8_t major_type;
	uint8_t additional_info;
	size_t header_len;
	size_t data_len;
	size_t edhoc_msg3_total_len;

	if (payload == NULL || edhoc_msg3 == NULL || oscore_payload == NULL) {
		return -EINVAL;
	}

	if (payload_len == 0U) {
		return -EINVAL;
	}

	/* RFC 9668 Section 3.2.1: COMB_PAYLOAD = EDHOC_MSG_3 || OSCORE_PAYLOAD.
	 * EDHOC_MSG_3 is a CBOR byte string (major type 2). Parse its header to
	 * find where OSCORE_PAYLOAD begins.
	 */
	initial_byte = payload[0];
	major_type = (initial_byte >> 5) & 0x07U;
	additional_info = initial_byte & 0x1fU;

	if (major_type != 2U) {
		LOG_ERR("EDHOC_MSG_3 must be CBOR byte string, got major type %u", major_type);
		return -EINVAL;
	}

	if (additional_info < 24U) {
		header_len = 1U;
		data_len = additional_info;
	} else if (additional_info == 24U) {
		if (payload_len < 2U) {
			return -EINVAL;
		}
		header_len = 2U;
		data_len = payload[1];
	} else if (additional_info == 25U) {
		if (payload_len < 3U) {
			return -EINVAL;
		}
		header_len = 3U;
		data_len = ((size_t)payload[1] << 8) | (size_t)payload[2];
	} else if (additional_info == 26U) {
		if (payload_len < 5U) {
			return -EINVAL;
		}
		header_len = 5U;
		data_len = ((size_t)payload[1] << 24) | ((size_t)payload[2] << 16) |
			   ((size_t)payload[3] << 8) | (size_t)payload[4];
	} else {
		/* 8-byte length (27) or reserved (28..31): reject. */
		LOG_ERR("Unsupported CBOR length encoding for EDHOC_MSG_3 (%u)", additional_info);
		return -EINVAL;
	}

	edhoc_msg3_total_len = header_len + data_len;
	if (edhoc_msg3_total_len > payload_len) {
		LOG_ERR("EDHOC_MSG_3 length (%zu) exceeds payload (%zu)",
			edhoc_msg3_total_len, payload_len);
		return -EINVAL;
	}

	edhoc_msg3->ptr = payload;
	edhoc_msg3->len = edhoc_msg3_total_len;
	oscore_payload->ptr = payload + edhoc_msg3_total_len;
	oscore_payload->len = payload_len - edhoc_msg3_total_len;

	/* RFC 9668 requires both parts to be present. */
	if (oscore_payload->len == 0U) {
		LOG_ERR("OSCORE_PAYLOAD missing in combined payload");
		return -EINVAL;
	}

	return 0;
}

int coap_edhoc_remove_option(struct coap_packet *cpkt)
{
	if (cpkt == NULL) {
		return -EINVAL;
	}

	return coap_packet_remove_option(cpkt, COAP_OPTION_EDHOC);
}

int coap_edhoc_encode_error(int err_code, const char *diag_msg,
			    uint8_t *out_buf, size_t *inout_len)
{
	size_t diag_len;
	size_t tstr_header_len;
	size_t offset = 0U;

	if (out_buf == NULL || inout_len == NULL || diag_msg == NULL) {
		return -EINVAL;
	}

	/* Only single-byte CBOR unsigned integers are supported for ERR_CODE. */
	if (err_code < 0 || err_code > 23) {
		LOG_ERR("Unsupported EDHOC error code %d (must be 0..23)", err_code);
		return -EINVAL;
	}

	diag_len = strlen(diag_msg);
	if (diag_len < 24U) {
		tstr_header_len = 1U;
	} else if (diag_len < 256U) {
		tstr_header_len = 2U;
	} else if (diag_len < 65536U) {
		tstr_header_len = 3U;
	} else {
		LOG_ERR("EDHOC diagnostic message too long (%zu bytes)", diag_len);
		return -EINVAL;
	}

	if (*inout_len < (1U + tstr_header_len + diag_len)) {
		return -ENOMEM;
	}

	/* ERR_CODE: CBOR unsigned integer (major type 0). */
	out_buf[offset++] = (uint8_t)err_code;

	/* ERR_INFO: CBOR text string (major type 3). */
	if (diag_len < 24U) {
		out_buf[offset++] = 0x60U | (uint8_t)diag_len;
	} else if (diag_len < 256U) {
		out_buf[offset++] = 0x78U;
		out_buf[offset++] = (uint8_t)diag_len;
	} else {
		out_buf[offset++] = 0x79U;
		out_buf[offset++] = (uint8_t)(diag_len >> 8);
		out_buf[offset++] = (uint8_t)(diag_len & 0xffU);
	}

	memcpy(out_buf + offset, diag_msg, diag_len);
	offset += diag_len;

	*inout_len = offset;

	return 0;
}
