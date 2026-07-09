.. _coap_oscore_interface:

OSCORE Support (RFC 8613)
#########################

.. contents::
    :local:
    :depth: 2


Overview
========

The Zephyr CoAP library provides support for Object Security for Constrained RESTful
Environments (OSCORE) as specified in :rfc:`8613`. OSCORE provides end-to-end protection
of CoAP messages using COSE (CBOR Object Signing and Encryption).

OSCORE protects CoAP messages at the application layer, providing:

1. **Confidentiality**: Message payloads and sensitive options are encrypted
2. **Integrity**: Messages are authenticated with a MAC
3. **Replay protection**: Sequence numbers prevent replay attacks
4. **Proxy-friendly**: Outer options remain visible for routing

Unlike DTLS, OSCORE provides end-to-end security that survives proxy translation
between different transport protocols (UDP, TCP, HTTP).

Configuration
=============

Enable OSCORE support with :kconfig:option:`CONFIG_COAP_OSCORE`. This option depends
on the uoscore-uedhoc module and PSA Crypto support:

.. code-block:: kconfig

   CONFIG_COAP_OSCORE=y
   CONFIG_UOSCORE=y
   CONFIG_PSA_CRYPTO=y

The uoscore module automatically selects required PSA crypto algorithms (AES-CCM,
HKDF-SHA256, etc.).

Server Usage
============

To enable OSCORE on a CoAP service, initialize an OSCORE security context and
attach it to the service. The context is created through the Zephyr OSCORE API;
applications do not include the underlying uoscore-uedhoc headers directly:

.. code-block:: c

   #include <zephyr/net/coap/coap_oscore.h>

   /* Key material must remain valid for the lifetime of the context. */
   static const uint8_t master_secret[16] = { /* ... */ };
   static const uint8_t master_salt[8] = { /* ... */ };
   static const uint8_t sender_id[] = { /* ... */ };
   static const uint8_t recipient_id[] = { /* ... */ };

   struct coap_oscore_context *oscore_ctx;
   struct coap_oscore_init_params params = {
       .master_secret = master_secret,
       .master_secret_len = sizeof(master_secret),
       .sender_id = sender_id,
       .sender_id_len = sizeof(sender_id),
       .recipient_id = recipient_id,
       .recipient_id_len = sizeof(recipient_id),
       .master_salt = master_salt,
       .master_salt_len = sizeof(master_salt),
       .aead_alg = COAP_OSCORE_AEAD_DEFAULT,
       .hkdf = COAP_OSCORE_HKDF_DEFAULT,
       .fresh_master_secret_salt = false,
   };

   int ret = coap_oscore_context_init(&params, &oscore_ctx);
   if (ret != 0) {
       /* Handle error */
   }

   /* Attach to service */
   my_service_data.oscore_ctx = oscore_ctx;

   /* Optionally require OSCORE for all requests */
   my_service_data.require_oscore = true;

The number of contexts that can be allocated at once is controlled by
:kconfig:option:`CONFIG_COAP_OSCORE_MAX_CONTEXTS`. Release a context with
``coap_oscore_context_free()`` once it is no longer attached to any client or
service.

When a service has an OSCORE context attached:

1. **Incoming requests**: The server automatically verifies and decrypts OSCORE-protected
   requests. Resource handlers receive decrypted CoAP messages with Inner options visible.

2. **Error handling**: OSCORE verification errors are sent as simple CoAP responses
   **without** OSCORE processing (RFC 8613 Section 8.2):

   - COSE decode failure → 4.02 Bad Option
   - Security context not found → 4.01 Unauthorized
   - Decryption failure → 4.00 Bad Request

3. **Required OSCORE**: If ``require_oscore`` is true, unprotected requests are rejected
   with 4.01 Unauthorized.

Security Context Derivation
============================

OSCORE security contexts are derived from a small set of parameters (RFC 8613 Section 3):

**Required parameters**:

- **Master Secret**: Shared secret (typically 16 bytes for AES-CCM-16-64-128)
- **Sender ID**: Unique identifier for the sender
- **Recipient ID**: Unique identifier for the recipient

**Optional parameters**:

- **Master Salt**: Additional entropy (recommended, typically 8 bytes)
- **ID Context**: Additional context identifier
- **AEAD Algorithm**: Defaults to AES-CCM-16-64-128
- **KDF**: Defaults to HKDF-SHA-256

These parameters are typically established through:

1. **Pre-shared keys**: Configured at device provisioning
2. **EDHOC**: Ephemeral Diffie-Hellman Over COSE (see uoscore-uedhoc module)

Security Considerations
=======================

1. **Sequence number overflow**: The sender sequence number (SSN) must not exceed 2^23-1
   for AES-CCM-16-64-128. The uoscore library enforces this limit.

2. **Master secret protection**: Master secrets must be stored securely (e.g., in
   secure storage or derived from EDHOC).

3. **Replay window**: The server maintains a replay window to detect and reject
   replayed requests.

4. **Fresh master secrets**: If master secrets are not re-derived after reboot (e.g.,
   using EDHOC), the sender sequence number must be persisted to non-volatile memory
   to prevent reuse.

5. **Token binding**: OSCORE maintains request-response binding through tokens and
   security context association (RFC 8613 Section 8).

API Reference
=============

.. doxygengroup:: coap_oscore
