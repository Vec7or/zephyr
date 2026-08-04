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
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>

#include "coap_edhoc.h"
#include "coap_edhoc_session.h"
#include "coap_edhoc_transport.h"
#include "coap_edhoc_wrappers.h"
#include "coap_oscore_ctx_cache.h"

/* CBOR simple value 'true', prepended to message_1 (RFC 9528 Appendix A.2.1). */
#define EDHOC_TRUE_PREFIX 0xF5U

#define EDHOC_MSG_BUF_LEN     256U
#define EDHOC_PRK_OUT_MAX_LEN 32U

/* Response buffer, used only while holding the CoAP server lock. */
static uint8_t edhoc_resp_buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];

static int send_edhoc_response(const struct coap_service *service,
			       const struct coap_packet *request, uint8_t code,
			       uint16_t content_format, const uint8_t *payload, size_t payload_len,
			       const struct net_sockaddr *addr, net_socklen_t addr_len)
{
	struct coap_packet response;
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint8_t tkl = coap_header_get_token(request, token);
	uint16_t id = coap_header_get_id(request);
	uint8_t type = (coap_header_get_type(request) == COAP_TYPE_CON) ? COAP_TYPE_ACK
								       : COAP_TYPE_NON_CON;
	int ret;

	ret = coap_packet_init(&response, edhoc_resp_buf, sizeof(edhoc_resp_buf), COAP_VERSION_1,
			       type, tkl, token, code, id);
	if (ret < 0) {
		return ret;
	}

	ret = coap_append_option_int(&response, COAP_OPTION_CONTENT_FORMAT, content_format);
	if (ret < 0) {
		return ret;
	}

	if (payload != NULL && payload_len > 0U) {
		ret = coap_packet_append_payload_marker(&response);
		if (ret < 0) {
			return ret;
		}

		ret = coap_packet_append_payload(&response, payload, payload_len);
		if (ret < 0) {
			return ret;
		}
	}

	return coap_service_send(service, &response, addr, addr_len, NULL);
}

static int send_edhoc_error(const struct coap_service *service, const struct coap_packet *request,
			    int err_code, const char *diag, uint8_t coap_code,
			    const struct net_sockaddr *addr, net_socklen_t addr_len)
{
	uint8_t err_buf[128];
	size_t err_len = sizeof(err_buf);
	int ret;

	ret = coap_edhoc_encode_error(err_code, diag, err_buf, &err_len);
	if (ret < 0) {
		LOG_ERR("Failed to encode EDHOC error (%d)", ret);
		return ret;
	}

	return send_edhoc_response(service, request, coap_code,
				   COAP_CONTENT_FORMAT_APP_EDHOC_CBOR_SEQ, err_buf, err_len, addr,
				   addr_len);
}

#if defined(CONFIG_ZTEST)
int coap_edhoc_transport_validate_content_format(const struct coap_packet *request)
#else
static int coap_edhoc_transport_validate_content_format(const struct coap_packet *request)
#endif
{
	struct coap_option opt[2];
	int count;
	int value;

	count = coap_find_options(request, COAP_OPTION_CONTENT_FORMAT, opt, 2);
	if (count == 0) {
		return -ENOENT;
	}
	if (count > 1) {
		return -EMSGSIZE;
	}

	value = coap_get_option_int(request, COAP_OPTION_CONTENT_FORMAT);
	if (value != COAP_CONTENT_FORMAT_APP_CID_EDHOC_CBOR_SEQ) {
		return -EBADMSG;
	}

	return 0;
}

/* Parse a connection identifier per RFC 9528 Section 3.3.2. A one-byte CBOR
 * integer is kept verbatim as the identifier; a byte string yields its content.
 */
static int parse_connection_identifier(const uint8_t *p, size_t len, uint8_t *cid,
				       uint8_t *cid_len, size_t *consumed)
{
	uint8_t b;
	uint8_t mt;
	uint8_t ai;

	if (len == 0U) {
		return -EINVAL;
	}

	b = p[0];
	mt = (b >> 5) & 0x07U;
	ai = b & 0x1fU;

	if (mt == 0U || mt == 1U) {
		/* Only one-byte integer encodings are valid connection IDs. */
		if (ai >= 24U) {
			return -EINVAL;
		}
		cid[0] = b;
		*cid_len = 1U;
		*consumed = 1U;
		return 0;
	}

	if (mt == 2U) {
		size_t header_len;
		size_t data_len;

		if (ai < 24U) {
			header_len = 1U;
			data_len = ai;
		} else if (ai == 24U) {
			if (len < 2U) {
				return -EINVAL;
			}
			header_len = 2U;
			data_len = p[1];
		} else {
			return -EINVAL;
		}

		if ((header_len + data_len) > len) {
			return -EINVAL;
		}
		if (data_len > COAP_EDHOC_CONN_ID_MAX_LEN) {
			return -EINVAL;
		}

		memcpy(cid, p + header_len, data_len);
		*cid_len = (uint8_t)data_len;
		*consumed = header_len + data_len;
		return 0;
	}

	return -EINVAL;
}

static int process_message_1(const struct coap_service *service, struct coap_packet *request,
			     const uint8_t *payload, size_t payload_len,
			     const struct net_sockaddr *addr, net_socklen_t addr_len)
{
	struct coap_edhoc_session *session;
	uint8_t msg2[EDHOC_MSG_BUF_LEN];
	size_t msg2_len = sizeof(msg2);
	uint8_t c_r[COAP_EDHOC_CONN_ID_MAX_LEN];
	size_t c_r_len = sizeof(c_r);
	int ret;

	/* Skip the 0xF5 true prefix (RFC 9528 Appendix A.2.1). */
	ret = coap_edhoc_msg2_gen_wrapper(NULL, NULL, payload + 1, payload_len - 1, msg2, &msg2_len,
					  c_r, &c_r_len);
	if (ret < 0) {
		LOG_WRN("EDHOC message_2 generation failed (%d)", ret);
		return send_edhoc_error(service, request, 1, "message_1 processing failed",
					COAP_RESPONSE_CODE_BAD_REQUEST, addr, addr_len);
	}

	if (c_r_len > COAP_EDHOC_CONN_ID_MAX_LEN) {
		LOG_ERR("EDHOC C_R too long (%zu)", c_r_len);
		return send_edhoc_error(service, request, 1, "internal error",
					COAP_RESPONSE_CODE_INTERNAL_ERROR, addr, addr_len);
	}

	session = coap_edhoc_session_insert(service->data->edhoc_session_cache,
					    CONFIG_COAP_EDHOC_SESSION_CACHE_SIZE, c_r,
					    (uint8_t)c_r_len);
	if (session == NULL) {
		LOG_ERR("Failed to allocate EDHOC session");
		return send_edhoc_error(service, request, 1, "no session slot",
					COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE, addr, addr_len);
	}

	return send_edhoc_response(service, request, COAP_RESPONSE_CODE_CHANGED,
				   COAP_CONTENT_FORMAT_APP_EDHOC_CBOR_SEQ, msg2, msg2_len, addr,
				   addr_len);
}

static int process_message_3(const struct coap_service *service, struct coap_packet *request,
			     const uint8_t *payload, size_t payload_len,
			     const struct net_sockaddr *addr, net_socklen_t addr_len)
{
	struct coap_edhoc_session *session;
	struct coap_oscore_ctx_cache_entry *entry;
	uint8_t c_r[COAP_EDHOC_CONN_ID_MAX_LEN];
	uint8_t c_r_len = 0U;
	uint8_t c_i[COAP_EDHOC_CONN_ID_MAX_LEN];
	size_t c_i_len = sizeof(c_i);
	uint8_t prk_out[EDHOC_PRK_OUT_MAX_LEN];
	size_t prk_out_len = sizeof(prk_out);
	uint8_t msg4[EDHOC_MSG_BUF_LEN];
	size_t msg4_len = sizeof(msg4);
	bool msg4_required = false;
	size_t consumed = 0U;
	int ret;

	ret = parse_connection_identifier(payload, payload_len, c_r, &c_r_len, &consumed);
	if (ret < 0) {
		LOG_WRN("Failed to parse C_R from message_3 (%d)", ret);
		return send_edhoc_error(service, request, 1, "malformed C_R",
					COAP_RESPONSE_CODE_BAD_REQUEST, addr, addr_len);
	}

	session = coap_edhoc_session_find(service->data->edhoc_session_cache,
					  CONFIG_COAP_EDHOC_SESSION_CACHE_SIZE, c_r, c_r_len);
	if (session == NULL) {
		LOG_WRN("No EDHOC session for C_R in message_3");
		return send_edhoc_error(service, request, 1, "unknown session",
					COAP_RESPONSE_CODE_BAD_REQUEST, addr, addr_len);
	}

	ret = coap_edhoc_msg3_process_wrapper(session->resp_ctx, session->runtime_ctx,
					      payload + consumed, payload_len - consumed, c_i,
					      &c_i_len, prk_out, &prk_out_len);
	if (ret < 0) {
		LOG_WRN("EDHOC message_3 processing failed (%d)", ret);
		coap_edhoc_session_remove(service->data->edhoc_session_cache,
					  CONFIG_COAP_EDHOC_SESSION_CACHE_SIZE, c_r, c_r_len);
		return send_edhoc_error(service, request, 1, "message_3 processing failed",
					COAP_RESPONSE_CODE_BAD_REQUEST, addr, addr_len);
	}

	if (c_i_len > COAP_EDHOC_CONN_ID_MAX_LEN) {
		(void)memset(prk_out, 0, sizeof(prk_out));
		coap_edhoc_session_remove(service->data->edhoc_session_cache,
					  CONFIG_COAP_EDHOC_SESSION_CACHE_SIZE, c_r, c_r_len);
		return send_edhoc_error(service, request, 1, "internal error",
					COAP_RESPONSE_CODE_INTERNAL_ERROR, addr, addr_len);
	}

	/* RFC 9528 Appendix A.1: responder Sender ID = C_I, Recipient ID = C_R. */
	entry = coap_oscore_ctx_cache_insert(service->data->oscore_ctx_cache,
					     CONFIG_COAP_OSCORE_CTX_CACHE_SIZE, c_r, c_r_len);
	if (entry == NULL) {
		(void)memset(prk_out, 0, sizeof(prk_out));
		coap_edhoc_session_remove(service->data->edhoc_session_cache,
					  CONFIG_COAP_EDHOC_SESSION_CACHE_SIZE, c_r, c_r_len);
		return send_edhoc_error(service, request, 1, "no context slot",
					COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE, addr, addr_len);
	}

	entry->master_secret_len = sizeof(entry->master_secret);
	ret = coap_edhoc_exporter_wrapper(prk_out, prk_out_len,
					  COAP_EDHOC_EXPORT_OSCORE_MASTER_SECRET,
					  entry->master_secret, &entry->master_secret_len);
	if (ret == 0) {
		entry->master_salt_len = sizeof(entry->master_salt);
		ret = coap_edhoc_exporter_wrapper(prk_out, prk_out_len,
						  COAP_EDHOC_EXPORT_OSCORE_MASTER_SALT,
						  entry->master_salt, &entry->master_salt_len);
	}

	(void)memset(prk_out, 0, sizeof(prk_out));

	if (ret < 0) {
		LOG_WRN("Failed to derive OSCORE key material (%d)", ret);
		coap_oscore_ctx_cache_remove(service->data->oscore_ctx_cache,
					     CONFIG_COAP_OSCORE_CTX_CACHE_SIZE, c_r, c_r_len);
		coap_edhoc_session_remove(service->data->edhoc_session_cache,
					  CONFIG_COAP_EDHOC_SESSION_CACHE_SIZE, c_r, c_r_len);
		return send_edhoc_error(service, request, 1, "key derivation failed",
					COAP_RESPONSE_CODE_INTERNAL_ERROR, addr, addr_len);
	}

	memcpy(entry->sender_id, c_i, c_i_len);
	entry->sender_id_len = (uint8_t)c_i_len;

	ret = coap_oscore_context_init_wrapper(&entry->ctx, entry->master_secret,
					       entry->master_secret_len, entry->master_salt,
					       entry->master_salt_len, entry->sender_id,
					       entry->sender_id_len, c_r, c_r_len);
	if (ret < 0) {
		LOG_WRN("Failed to initialize EDHOC-derived OSCORE context (%d)", ret);
		coap_oscore_ctx_cache_remove(service->data->oscore_ctx_cache,
					     CONFIG_COAP_OSCORE_CTX_CACHE_SIZE, c_r, c_r_len);
		coap_edhoc_session_remove(service->data->edhoc_session_cache,
					  CONFIG_COAP_EDHOC_SESSION_CACHE_SIZE, c_r, c_r_len);
		return send_edhoc_error(service, request, 1, "context setup failed",
					COAP_RESPONSE_CODE_INTERNAL_ERROR, addr, addr_len);
	}

	ret = coap_edhoc_msg4_gen_wrapper(session->resp_ctx, session->runtime_ctx, msg4, &msg4_len,
					  &msg4_required);
	if (ret < 0) {
		LOG_WRN("EDHOC message_4 generation failed (%d)", ret);
		msg4_required = false;
		msg4_len = 0U;
	}

	/* Handshake complete; the session state is no longer needed. */
	coap_edhoc_session_remove(service->data->edhoc_session_cache,
				  CONFIG_COAP_EDHOC_SESSION_CACHE_SIZE, c_r, c_r_len);

	return send_edhoc_response(service, request, COAP_RESPONSE_CODE_CHANGED,
				   COAP_CONTENT_FORMAT_APP_EDHOC_CBOR_SEQ,
				   msg4_required ? msg4 : NULL, msg4_required ? msg4_len : 0U, addr,
				   addr_len);
}

int coap_edhoc_transport_handle_request(const struct coap_service *service,
					struct coap_packet *request,
					const struct net_sockaddr *addr, net_socklen_t addr_len)
{
	const uint8_t *payload;
	uint16_t payload_len;
	int ret;

	if (coap_header_get_code(request) != COAP_METHOD_POST) {
		LOG_WRN("EDHOC resource only accepts POST");
		return send_edhoc_response(service, request, COAP_RESPONSE_CODE_NOT_ALLOWED,
					   COAP_CONTENT_FORMAT_APP_EDHOC_CBOR_SEQ, NULL, 0U, addr,
					   addr_len);
	}

	ret = coap_edhoc_transport_validate_content_format(request);
	if (ret < 0) {
		const char *msg;

		switch (ret) {
		case -ENOENT:
			msg = "missing Content-Format";
			break;
		case -EMSGSIZE:
			msg = "duplicate Content-Format";
			break;
		default:
			msg = "invalid Content-Format";
			break;
		}
		LOG_WRN("EDHOC request Content-Format invalid: %s", msg);
		return send_edhoc_error(service, request, 1, msg, COAP_RESPONSE_CODE_BAD_REQUEST,
					addr, addr_len);
	}

	payload = coap_packet_get_payload(request, &payload_len);
	if (payload == NULL || payload_len == 0U) {
		LOG_WRN("EDHOC request missing payload");
		return send_edhoc_error(service, request, 1, "empty payload",
					COAP_RESPONSE_CODE_BAD_REQUEST, addr, addr_len);
	}

	/* RFC 9528 Appendix A.2: message_1 is prefixed with CBOR true (0xF5);
	 * message_3 begins with the connection identifier C_R.
	 */
	if (payload[0] == EDHOC_TRUE_PREFIX) {
		return process_message_1(service, request, payload, payload_len, addr, addr_len);
	}

	return process_message_3(service, request, payload, payload_len, addr, addr_len);
}
