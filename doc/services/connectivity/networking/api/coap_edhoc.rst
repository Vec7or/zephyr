.. _coap_edhoc_interface:

EDHOC Support (RFC 9668 / RFC 9528)
###################################

.. contents::
    :local:
    :depth: 2

Overview
========

The Zephyr CoAP library provides server-side support for Ephemeral
Diffie-Hellman Over COSE (EDHOC) as specified in :rfc:`9528`, and for the
EDHOC and OSCORE combined request specified in :rfc:`9668`. EDHOC is a
lightweight authenticated key exchange that establishes an OSCORE security
context (see :ref:`coap_oscore_interface`) between a client (initiator) and a
server (responder).

Two server-side features are provided:

1. **EDHOC over CoAP transport** at ``/.well-known/edhoc`` (:rfc:`9528`
   Appendix A.2), carrying the forward message flow (``message_1`` ..
   ``message_4``).
2. **EDHOC + OSCORE combined request** (:rfc:`9668`), which carries EDHOC
   ``message_3`` together with the first OSCORE-protected application request in
   a single CoAP message, using the EDHOC option (21).

.. note::

   The CoAP library provides the protocol plumbing (option handling, combined
   payload parsing, session and context management, transport resource and
   discovery). The EDHOC cryptographic steps are delegated to weak wrapper
   functions (see below). Without a linked EDHOC backend these wrappers return
   ``-ENOTSUP`` and the handshake cannot complete.

Client-side EDHOC is not provided.

Configuration
=============

Enable EDHOC support with the following Kconfig options:

.. code-block:: cfg

   CONFIG_COAP_EDHOC=y
   CONFIG_COAP_EDHOC_COMBINED_REQUEST=y
   CONFIG_COAP_SERVER_WELL_KNOWN_EDHOC=y

Additional options:

- :kconfig:option:`CONFIG_COAP_EDHOC_MAX_COMBINED_PAYLOAD_LEN`: Maximum combined
  payload length (default 1024).
- :kconfig:option:`CONFIG_COAP_EDHOC_SESSION_CACHE_SIZE`: Number of concurrent
  EDHOC sessions per service.
- :kconfig:option:`CONFIG_COAP_EDHOC_SESSION_LIFETIME_MS`: Lifetime of an
  incomplete EDHOC session.
- :kconfig:option:`CONFIG_COAP_OSCORE_CTX_CACHE_SIZE`: Number of EDHOC-derived
  OSCORE contexts cached per service.
- :kconfig:option:`CONFIG_COAP_OSCORE_CTX_LIFETIME_MS`: Lifetime of a cached
  EDHOC-derived OSCORE context.
- :kconfig:option:`CONFIG_COAP_EDHOC_COMBINED_OUTER_BLOCK_CACHE_SIZE`,
  :kconfig:option:`CONFIG_COAP_EDHOC_COMBINED_OUTER_BLOCK_LIFETIME_MS`,
  :kconfig:option:`CONFIG_COAP_EDHOC_COMBINED_OUTER_BLOCK_MAX_LEN`: Outer Block1
  reassembly limits (:rfc:`9668` Section 3.3.2 Step 0).

.. important::

   A service that accepts EDHOC handshakes and combined requests must not set
   ``oscore_required``, because the ``/.well-known/edhoc`` handshake and the
   EDHOC part of a combined request are unprotected.

EDHOC backend
=============

The following weak wrapper functions form the integration seam with a concrete
EDHOC implementation (for example the ``uoscore-uedhoc`` module). Provide strong
definitions to enable the handshake:

- ``coap_edhoc_msg2_gen_wrapper()`` -- process ``message_1``, produce
  ``message_2`` and select ``C_R``.
- ``coap_edhoc_msg3_process_wrapper()`` -- process ``message_3``, output ``C_I``
  and ``PRK_out``.
- ``coap_edhoc_msg4_gen_wrapper()`` -- optionally produce ``message_4``.
- ``coap_edhoc_exporter_wrapper()`` -- derive the OSCORE Master Secret and Master
  Salt from ``PRK_out``.
- ``coap_oscore_context_init_wrapper()`` -- initialize the OSCORE context
  (default implementation calls ``coap_oscore_context_init()``).

Per :rfc:`9528` Appendix A.1 the responder uses OSCORE Sender ID = ``C_I`` and
Recipient ID = ``C_R``.

Discovery
=========

When :kconfig:option:`CONFIG_COAP_SERVER_WELL_KNOWN_EDHOC` is enabled, the
server advertises a synthetic ``</.well-known/edhoc>;rt=core.edhoc;ed-r;ed-comb-req``
link in ``/.well-known/core`` responses (:rfc:`9668` Section 6). The synthetic
entry participates in query filtering and is suppressed when the application
registers its own ``/.well-known/edhoc`` resource.

Limitations
===========

- Response protection for a combined request currently uses the service OSCORE
  context rather than the per-client EDHOC-derived context.
- The synthetic discovery link is emitted on the non-block-wise
  ``/.well-known/core`` path.
