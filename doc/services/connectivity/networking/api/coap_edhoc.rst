.. _coap_edhoc_interface:

EDHOC Support (RFC 9528)
########################

.. contents::
    :local:
    :depth: 2

Overview
========

The Zephyr CoAP library provides server-side support for Ephemeral
Diffie-Hellman Over COSE (EDHOC) as specified in :rfc:`9528`. EDHOC is a
lightweight authenticated key exchange that establishes an OSCORE security
context (see :ref:`coap_oscore_interface`) between a client (initiator) and a
server (responder).

The server exposes the **EDHOC over CoAP transport** at ``/.well-known/edhoc``
(:rfc:`9528` Appendix A.2), carrying the forward message flow: ``message_1`` and
``message_3`` from the initiator, ``message_2`` in the responses. On completion
an OSCORE security context is derived and installed, which the client then uses
with ordinary OSCORE requests (see :ref:`coap_oscore_interface`).

.. note::

   The MVP supports EDHOC method 3 (static Diffie-Hellman authentication on both
   sides) and cipher suite 2 (P-256, AES-CCM-16-64-128, SHA-256). ``message_4``,
   the EDHOC + OSCORE combined request (:rfc:`9668`) and client-side EDHOC are
   not provided.

The cryptographic handshake is performed by the ``uoscore-uedhoc`` module
(:kconfig:option:`CONFIG_UEDHOC`). The credentials are loaded from Zephyr TLS
credential storage (sec_tag) and selected with
:c:func:`coap_edhoc_set_sec_tag_config`.

Configuration
=============

Enable EDHOC support with the following Kconfig options:

.. code-block:: cfg

   CONFIG_COAP_OSCORE=y
   CONFIG_COAP_EDHOC=y
   CONFIG_COAP_SERVER_WELL_KNOWN_EDHOC=y

:kconfig:option:`CONFIG_COAP_EDHOC` depends on :kconfig:option:`CONFIG_COAP_OSCORE`
and selects :kconfig:option:`CONFIG_UEDHOC` and
:kconfig:option:`CONFIG_TLS_CREDENTIALS`. Additional options:

- :kconfig:option:`CONFIG_COAP_EDHOC_CACHE_SIZE`: Number of device-global
  EDHOC cache entries, each tracking one C_R across its handshake and derived
  OSCORE context.
- :kconfig:option:`CONFIG_COAP_EDHOC_SESSION_LIFETIME_MS`: Lifetime of an
  incomplete EDHOC session.
- :kconfig:option:`CONFIG_COAP_OSCORE_CTX_LIFETIME_MS`: Lifetime of a cached
  EDHOC-derived OSCORE context.
- :kconfig:option:`CONFIG_COAP_EDHOC_MAX_DER_SIZE`: Maximum size of a DER
  credential blob fetched from sec_tag storage.
- :kconfig:option:`CONFIG_COAP_EDHOC_MAX_CRED_SIZE`: Size of each converted
  ``CRED`` buffer.

Credentials
===========

The responder identity and the trusted initiator credentials are loaded from
Zephyr TLS credential storage (sec_tag). Register the responder's X.509
certificate and P-256 private key, and the trusted initiator's certificate, with
:c:func:`tls_credential_add`, then select them with
:c:func:`coap_edhoc_set_sec_tag_config`:

.. code-block:: c

   static const struct coap_edhoc_sec_tag_config edhoc_cfg = {
           .responder_sec_tag = RESPONDER_TAG,
           .initiator_sec_tag = INITIATOR_TAG,
   };

   tls_credential_add(RESPONDER_TAG, TLS_CREDENTIAL_PUBLIC_CERTIFICATE,
                      responder_cert_der, sizeof(responder_cert_der));
   tls_credential_add(RESPONDER_TAG, TLS_CREDENTIAL_PRIVATE_KEY,
                      responder_key_der, sizeof(responder_key_der));
   tls_credential_add(INITIATOR_TAG, TLS_CREDENTIAL_CA_CERTIFICATE,
                      initiator_cert_der, sizeof(initiator_cert_der));

   coap_edhoc_set_sec_tag_config(&edhoc_cfg);

The server fetches the DER material, extracts the static Diffie-Hellman keys,
wraps each certificate as ``CRED`` and derives ``ID_CRED`` from the COSE x5t
certificate thumbprint. Until a configuration is installed the handshake cannot
complete; pass ``NULL`` to :c:func:`coap_edhoc_set_sec_tag_config` to clear it.
Per :rfc:`9528` Appendix A.1 the responder uses OSCORE Sender ID = ``C_I`` and
Recipient ID = ``C_R``. The MVP binds to one responder identity and one trusted
initiator identity, and only supports cipher suite 2 (P-256, DER/X.509
credentials).

Discovery
=========

When :kconfig:option:`CONFIG_COAP_SERVER_WELL_KNOWN_EDHOC` is enabled, the
server advertises a synthetic ``</.well-known/edhoc>;rt=core.edhoc;ed-r`` link in
``/.well-known/core`` responses. The synthetic entry participates in query
filtering and is suppressed when the application registers its own
``/.well-known/edhoc`` resource.

API Reference
=============

.. doxygengroup:: coap_edhoc

Limitations
===========

- Only EDHOC method 3 and cipher suite 2 are supported.
- ``message_4`` and the EDHOC + OSCORE combined request (:rfc:`9668`) are not
  supported.
- Connection identifiers ``C_R`` are single-byte values.
- The synthetic discovery link is emitted on the non-block-wise
  ``/.well-known/core`` path.

