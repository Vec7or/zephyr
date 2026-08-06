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
#include <zephyr/random/random.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zephyr/net/coap_oscore.h>
#include <zephyr/net/coap_edhoc.h>

/* uoscore-uedhoc's buffer_sizes.h redefines MAX/MIN; drop Zephyr's first. */
#undef MAX
#undef MIN
#include "edhoc_internal.h"
#include "edhoc/suites.h"

#include "coap_edhoc.h"
#include "coap_edhoc_cache.h"
#include "coap_edhoc_transport.h"

/* CBOR simple value 'true', prepended to message_1 (RFC 9528 Appendix A.2.1). */
#define EDHOC_TRUE_PREFIX 0xF5U

#define EDHOC_MSG_BUF_LEN 256U

/* OSCORE key material lengths for AES-CCM-16-64-128 (RFC 8613 Section 3.2). */
#define EDHOC_OSCORE_MASTER_SECRET_LEN 16U
#define EDHOC_OSCORE_MASTER_SALT_LEN   8U

/* Per-handshake EDHOC state. Kept in a transport-private pool so the heavy
 * uoscore-uedhoc context structures stay out of the public CoAP headers. The
 * responder role is device-scoped, so a single global pool is used.
 */
struct edhoc_handshake_state {
	struct edhoc_responder_context resp;
	struct runtime_context rc;
	uint8_t c_r_buf[COAP_EDHOC_CONN_ID_MAX_LEN];
	uint8_t c_i_buf[COAP_EDHOC_CONN_ID_MAX_LEN];
	uint8_t c_i_len;
	uint8_t y_buf[P_256_PRIV_KEY_SIZE];
	uint8_t g_y_buf[G_Y_SIZE];
	uint8_t suites_r_buf[1];
	struct coap_edhoc_credentials creds;
	bool in_use;
};

static struct edhoc_handshake_state edhoc_states[CONFIG_COAP_EDHOC_CACHE_SIZE];

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

/* Map a uoscore-uedhoc enum err to a negative errno (0 on success). */
static int edhoc_err(enum err e)
{
	return (e == ok) ? 0 : -EIO;
}

static struct edhoc_handshake_state *edhoc_state_alloc(void)
{
	for (size_t i = 0; i < ARRAY_SIZE(edhoc_states); i++) {
		if (!edhoc_states[i].in_use) {
			memset(&edhoc_states[i], 0, sizeof(edhoc_states[i]));
			edhoc_states[i].in_use = true;
			return &edhoc_states[i];
		}
	}

	return NULL;
}

static void edhoc_state_free(void *state)
{
	struct edhoc_handshake_state *st = state;

	if (st != NULL) {
		memset(st, 0, sizeof(*st));
	}
}

static void edhoc_cache_drop(const uint8_t *c_r, uint8_t c_r_len)
{
	struct coap_edhoc_cache_entry *e;

	e = coap_edhoc_cache_find(c_r, c_r_len);
	if (e != NULL) {
		edhoc_state_free(e->handshake);
		coap_edhoc_cache_remove(c_r, c_r_len);
	}
}

/* Populate the uoscore-uedhoc responder context for method 3 (static DH on both
 * sides). Credential buffers are referenced from the application-supplied
 * struct, which the library only reads.
 */
static void resp_ctx_build(struct edhoc_handshake_state *st, const uint8_t *c_r, uint8_t c_r_len)
{
	struct edhoc_responder_context *c = &st->resp;

	memcpy(st->c_r_buf, c_r, c_r_len);
	st->suites_r_buf[0] = (uint8_t)SUITE_2;

	memset(c, 0, sizeof(*c));
	c->sock = NULL;
	c->c_r.ptr = st->c_r_buf;
	c->c_r.len = c_r_len;
	c->suites_r.ptr = st->suites_r_buf;
	c->suites_r.len = sizeof(st->suites_r_buf);
	c->g_y.ptr = st->g_y_buf;
	c->g_y.len = sizeof(st->g_y_buf);
	c->y.ptr = st->y_buf;
	c->y.len = sizeof(st->y_buf);
	c->g_r.ptr = (uint8_t *)st->creds.g_r;
	c->g_r.len = (uint32_t)st->creds.g_r_len;
	c->r.ptr = (uint8_t *)st->creds.r;
	c->r.len = (uint32_t)st->creds.r_len;
	c->id_cred_r.ptr = (uint8_t *)st->creds.id_cred_r;
	c->id_cred_r.len = (uint32_t)st->creds.id_cred_r_len;
	c->cred_r.ptr = (uint8_t *)st->creds.cred_r;
	c->cred_r.len = (uint32_t)st->creds.cred_r_len;
	c->ead_2 = NULL_ARRAY;
	c->ead_4 = NULL_ARRAY;
	c->sk_r = NULL_ARRAY;
	c->pk_r = NULL_ARRAY;
}

/* Process EDHOC message_1 and produce message_2 (RFC 9528 Appendix A.2.1). */
static int edhoc_backend_msg1(struct edhoc_handshake_state *st, const uint8_t *c_r, uint8_t c_r_len,
			      const uint8_t *msg1, size_t msg1_len, uint8_t *msg2, size_t *msg2_len)
{
	struct byte_array c_i = {.len = sizeof(st->c_i_buf), .ptr = st->c_i_buf};
	int ret;

	ret = coap_edhoc_acquire_credentials(&st->creds);
	if (ret < 0) {
		return ret;
	}

	resp_ctx_build(st, c_r, c_r_len);

	/* Fresh ephemeral P-256 key pair (suite 2); PSA supplies the randomness. */
	ret = edhoc_err(ephemeral_dh_key_gen(P256, 0, &st->resp.y, &st->resp.g_y));
	if (ret < 0) {
		return ret;
	}

	runtime_context_init(&st->rc);

	if (msg1_len > sizeof(st->rc.msg_buf)) {
		return -EMSGSIZE;
	}
	memcpy(st->rc.msg_buf, msg1, msg1_len);
	st->rc.msg.ptr = st->rc.msg_buf;
	st->rc.msg.len = (uint32_t)msg1_len;

	ret = edhoc_err(msg2_gen(&st->resp, &st->rc, &c_i));
	if (ret < 0) {
		return ret;
	}

	if (c_i.len > sizeof(st->c_i_buf)) {
		return -EINVAL;
	}
	st->c_i_len = (uint8_t)c_i.len;

	if (st->rc.msg.len > *msg2_len) {
		return -ENOMEM;
	}
	memcpy(msg2, st->rc.msg.ptr, st->rc.msg.len);
	*msg2_len = st->rc.msg.len;

	return 0;
}

/* Process EDHOC message_3 and derive the OSCORE key material (RFC 9528 A.1). */
static int edhoc_backend_msg3(struct edhoc_handshake_state *st, const uint8_t *msg3,
			      size_t msg3_len, uint8_t *master_secret, size_t *ms_len,
			      uint8_t *master_salt, size_t *salt_len)
{
	struct other_party_cred cred_i = {0};
	struct cred_array cred_i_array = {.len = 1, .ptr = &cred_i};
	uint8_t prk_out_buf[PRK_SIZE];
	uint8_t prk_exp_buf[PRK_SIZE];
	struct byte_array prk_out = {.len = sizeof(prk_out_buf), .ptr = prk_out_buf};
	struct byte_array prk_exp = {.len = sizeof(prk_exp_buf), .ptr = prk_exp_buf};
	struct byte_array ms = {.len = EDHOC_OSCORE_MASTER_SECRET_LEN, .ptr = master_secret};
	struct byte_array salt = {.len = EDHOC_OSCORE_MASTER_SALT_LEN, .ptr = master_salt};
	int ret;

	cred_i.id_cred.ptr = (uint8_t *)st->creds.id_cred_i;
	cred_i.id_cred.len = (uint32_t)st->creds.id_cred_i_len;
	cred_i.cred.ptr = (uint8_t *)st->creds.cred_i;
	cred_i.cred.len = (uint32_t)st->creds.cred_i_len;
	cred_i.g.ptr = (uint8_t *)st->creds.g_i;
	cred_i.g.len = (uint32_t)st->creds.g_i_len;

	if (msg3_len > sizeof(st->rc.msg_buf)) {
		return -EMSGSIZE;
	}
	memcpy(st->rc.msg_buf, msg3, msg3_len);
	st->rc.msg.ptr = st->rc.msg_buf;
	st->rc.msg.len = (uint32_t)msg3_len;

	ret = edhoc_err(msg3_process(&st->resp, &st->rc, &cred_i_array, &prk_out, NULL));
	if (ret == 0) {
		ret = edhoc_err(prk_out2exporter(SHA_256, &prk_out, &prk_exp));
	}
	if (ret == 0) {
		ret = edhoc_err(edhoc_exporter(SHA_256, OSCORE_MASTER_SECRET, &prk_exp, &ms));
	}
	if (ret == 0) {
		ret = edhoc_err(edhoc_exporter(SHA_256, OSCORE_MASTER_SALT, &prk_exp, &salt));
	}

	(void)memset(prk_out_buf, 0, sizeof(prk_out_buf));
	(void)memset(prk_exp_buf, 0, sizeof(prk_exp_buf));

	if (ret < 0) {
		return ret;
	}

	*ms_len = ms.len;
	*salt_len = salt.len;

	return 0;
}

static int edhoc_oscore_ctx_init(struct coap_edhoc_cache_entry *entry, const uint8_t *c_r,
				 uint8_t c_r_len)
{
	struct coap_oscore_init_params params = {
		.master_secret = entry->master_secret,
		.master_secret_len = entry->master_secret_len,
		.master_salt = entry->master_salt,
		.master_salt_len = entry->master_salt_len,
		.sender_id = entry->sender_id,
		.sender_id_len = entry->sender_id_len,
		.recipient_id = c_r,
		.recipient_id_len = c_r_len,
		.aead_alg = COAP_OSCORE_AEAD_AES_CCM_16_64_128,
		.hkdf = COAP_OSCORE_HKDF_SHA_256,
		.fresh_master_secret_salt = true,
	};

	return coap_oscore_context_init(&params, &entry->ctx);
}

/* Pick a one-byte responder connection identifier not currently in use. */
static int pick_c_r(uint8_t *c_r, uint8_t *c_r_len)
{
	for (int i = 0; i < 16; i++) {
		uint8_t candidate = sys_rand8_get();

		if (coap_edhoc_cache_find(&candidate, 1U) == NULL) {
			c_r[0] = candidate;
			*c_r_len = 1U;
			return 0;
		}
	}

	return -EAGAIN;
}

static int process_message_1(const struct coap_service *service, struct coap_packet *request,
			     const uint8_t *payload, size_t payload_len,
			     const struct net_sockaddr *addr, net_socklen_t addr_len)
{
	struct coap_edhoc_cache_entry *entry;
	struct edhoc_handshake_state *st;
	uint8_t msg2[EDHOC_MSG_BUF_LEN];
	size_t msg2_len = sizeof(msg2);
	uint8_t c_r[COAP_EDHOC_CONN_ID_MAX_LEN];
	uint8_t c_r_len = 0U;
	int ret;

	ret = pick_c_r(c_r, &c_r_len);
	if (ret < 0) {
		LOG_WRN("No free EDHOC C_R (%d)", ret);
		return send_edhoc_error(service, request, 1, "no connection id",
					COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE, addr, addr_len);
	}

	entry = coap_edhoc_cache_insert(c_r, c_r_len);
	if (entry == NULL) {
		LOG_ERR("Failed to allocate EDHOC session");
		return send_edhoc_error(service, request, 1, "no session slot",
					COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE, addr, addr_len);
	}

	st = edhoc_state_alloc();
	if (st == NULL) {
		coap_edhoc_cache_remove(c_r, c_r_len);
		LOG_ERR("No free EDHOC handshake state");
		return send_edhoc_error(service, request, 1, "no session slot",
					COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE, addr, addr_len);
	}
	entry->handshake = st;

	/* Skip the 0xF5 true prefix (RFC 9528 Appendix A.2.1). */
	ret = edhoc_backend_msg1(st, c_r, c_r_len, payload + 1, payload_len - 1, msg2, &msg2_len);
	if (ret < 0) {
		LOG_WRN("EDHOC message_1 processing failed (%d)", ret);
		edhoc_cache_drop(c_r, c_r_len);
		return send_edhoc_error(service, request, 1, "message_1 processing failed",
					COAP_RESPONSE_CODE_BAD_REQUEST, addr, addr_len);
	}

	return send_edhoc_response(service, request, COAP_RESPONSE_CODE_CHANGED,
				   COAP_CONTENT_FORMAT_APP_EDHOC_CBOR_SEQ, msg2, msg2_len, addr,
				   addr_len);
}

static int process_message_3(const struct coap_service *service, struct coap_packet *request,
			     const uint8_t *payload, size_t payload_len,
			     const struct net_sockaddr *addr, net_socklen_t addr_len)
{
	struct coap_edhoc_cache_entry *entry;
	struct edhoc_handshake_state *st;
	uint8_t c_r[COAP_EDHOC_CONN_ID_MAX_LEN];
	uint8_t c_r_len = 0U;
	size_t consumed = 0U;
	int ret;

	ret = parse_connection_identifier(payload, payload_len, c_r, &c_r_len, &consumed);
	if (ret < 0) {
		LOG_WRN("Failed to parse C_R from message_3 (%d)", ret);
		return send_edhoc_error(service, request, 1, "malformed C_R",
					COAP_RESPONSE_CODE_BAD_REQUEST, addr, addr_len);
	}

	entry = coap_edhoc_cache_find(c_r, c_r_len);
	if (entry == NULL || entry->state != COAP_EDHOC_CACHE_HANDSHAKING ||
	    entry->handshake == NULL) {
		LOG_WRN("No EDHOC session for C_R in message_3");
		return send_edhoc_error(service, request, 1, "unknown session",
					COAP_RESPONSE_CODE_BAD_REQUEST, addr, addr_len);
	}
	st = entry->handshake;

	ret = edhoc_backend_msg3(st, payload + consumed, payload_len - consumed,
				 entry->master_secret, &entry->master_secret_len,
				 entry->master_salt, &entry->master_salt_len);
	if (ret < 0) {
		LOG_WRN("EDHOC message_3 processing failed (%d)", ret);
		edhoc_cache_drop(c_r, c_r_len);
		return send_edhoc_error(service, request, 1, "message_3 processing failed",
					COAP_RESPONSE_CODE_BAD_REQUEST, addr, addr_len);
	}

	/* RFC 9528 Appendix A.1: responder Sender ID = C_I, Recipient ID = C_R. */
	if (st->c_i_len > sizeof(entry->sender_id)) {
		edhoc_cache_drop(c_r, c_r_len);
		return send_edhoc_error(service, request, 1, "internal error",
					COAP_RESPONSE_CODE_INTERNAL_ERROR, addr, addr_len);
	}
	memcpy(entry->sender_id, st->c_i_buf, st->c_i_len);
	entry->sender_id_len = st->c_i_len;

	ret = edhoc_oscore_ctx_init(entry, c_r, c_r_len);
	if (ret < 0) {
		LOG_WRN("Failed to initialize EDHOC-derived OSCORE context (%d)", ret);
		edhoc_cache_drop(c_r, c_r_len);
		return send_edhoc_error(service, request, 1, "context setup failed",
					COAP_RESPONSE_CODE_INTERNAL_ERROR, addr, addr_len);
	}

	/* Handshake complete: release the handshake state and keep the derived
	 * OSCORE context cached under the same C_R. message_4 is optional and
	 * not used here.
	 */
	edhoc_state_free(entry->handshake);
	entry->handshake = NULL;
	entry->state = COAP_EDHOC_CACHE_COMPLETED;
	entry->timestamp = k_uptime_get();

	return send_edhoc_response(service, request, COAP_RESPONSE_CODE_CHANGED,
				   COAP_CONTENT_FORMAT_APP_EDHOC_CBOR_SEQ, NULL, 0U, addr, addr_len);
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
