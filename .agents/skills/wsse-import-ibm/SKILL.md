---
name: wsse-import-ibm
description: Use when turning an IBM WebSphere WS-Security configuration into php-soap/psr18-wsse-middleware wiring. Triggers on a ws-security.xml file, an ibm-webservicesclient-ext.xmi / ibm-webservicesclient-bnd.xmi / ibm-webservices-ext.xmi / ibm-webservices-bnd.xmi descriptor, a WebSphere policy set with policy.xml and bindings.xml, element names like signingInfo, encryptionInfo, keyLocators, trustAnchors, tokenGenerator or tokenConsumer, and on requests like "the client sent us their WebSphere config, what blocks do we need".
---

# Importing an IBM WebSphere WS-Security configuration

Two references, both required:

- [Shared import rules](../../references/wsse-import-rules.md): mirror or copy, the three rules, what to do with
  unmapped settings, and how the result gets verified.
- [The WebSphere descriptor formats](references/ibm-descriptors.md): which file holds what, the override chain,
  and the mapping table for every setting.

## Procedure

1. **Check the file set is complete before mapping anything.** The file named `ws-security.xml` carries key
   material for a whole WebSphere cell and says nothing about which parts are protected. On its own it cannot
   produce a configuration. Ask for the `ibm-webservices*-ext.xmi` and `-bnd.xmi` descriptors, or for a policy
   set's `policy.xml`, and say plainly that you are blocked without them.

2. **Establish direction.** Usually you hold the service's own descriptors, so you are mirroring: their
   `securityRequestReceiverServiceConfig` drives your `outbound`, their
   `securityResponseSenderServiceConfig` drives your `inbound`. If the filenames contain `client`, you may be
   holding another consumer's configuration, which is a copy instead. Get this right before anything else.

3. **Resolve the override chain and the port.** Application binding beats server file beats cell file. Settings
   are scoped per port (`serviceRefs/portQnameBindings`, `pcBindings`), while a `WsseMiddleware` is configured
   once per client, so ask which port this client speaks to. Two ports that disagree are two middlewares.

4. **Note which vocabulary generation you are reading.** WAS 5 uses `signingInfo` with `references`; WAS 6 adds
   `partReference`, `transform`, `tokenGenerator`, `tokenConsumer` and a `keyInfo` element with a `type`
   attribute. The reference covers both.

5. **Map in this order**: blocks, parts, algorithms, key references, then trust and key material. Watch the one
   place where an IBM keyword and our default disagree: `bodycontent` is plain `Part::body()`, while `body` under
   confidentiality needs an explicit encryption mode.

6. **Expect most of the key material to be unmappable.** Every keystore here is a JKS or JCEKS, and the
   `keyLocators`, `tokenGenerator` and `tokenConsumer` entries name Java classes. Ask, rather than approximating.

7. **Hand over a draft** with the unmapped list and the verification steps from the shared rules.

## Output shape

- The `WsseMiddleware` construction, ready to paste, spelling out only what departs from the defaults.
- Each departure traced to the descriptor setting that caused it.
- Unmapped items, as questions.
- The verification steps, unedited.
