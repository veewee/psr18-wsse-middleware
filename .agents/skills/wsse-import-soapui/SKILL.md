---
name: wsse-import-soapui
description: Use when turning a SoapUI or ReadyAPI WS-Security setup into php-soap/psr18-wsse-middleware wiring. Triggers on a *-soapui-project.xml file, a con:wssContainer or con:outgoing block, an outgoingWss reference, a screenshot or description of the SoapUI WS-Security panel, and on requests like "we have this working in SoapUI, do the same in PHP" or "port my SoapUI security config".
---

# Importing a SoapUI WS-Security configuration

This is the common case. A SoapUI project that already talks to the service is the best specification you can
get, because someone made it work against the live peer.

Two references, both required:

- [Shared import rules](../../references/wsse-import-rules.md): mirror or copy, the three rules, what to do with
  unmapped settings, and how the result gets verified.
- [The SoapUI project format](references/soapui-project.md): where the settings sit in the XML, and the mapping
  table for every entry type.

## Procedure

1. **Find the configuration.** In the project XML, look for `<con:wssContainer>`. Keystores are `<con:crypto>`
   entries; outgoing configurations are `<con:outgoing>` blocks, each with a `<con:name>`. A request selects one
   by `outgoingWss="<name>"`, so check which name the request you care about actually uses. A project with
   several outgoing configurations usually has several that are unused.

2. **This is a copy, not a mirror.** A SoapUI outgoing configuration is a client configuration, so its entries
   map to your `outbound` list in the same direction. Any `<con:incoming>` block maps to `inbound`.

3. **Map in entry order.** The order of `<con:entry>` elements is the order SoapUI applies them, and block order
   matters here too: sign before you encrypt. Keep it.

4. **Read the reference for every entry type** rather than guessing from the type attribute. Two traps in
   particular: an empty Parts table means *the whole message*, not nothing, and `keyIdentifierType` is a numeric
   WSS4J constant whose meaning is not obvious from the digit.

5. **Ask about the keystore.** SoapUI points at a JKS or PKCS#12 file with a plaintext password in the project.
   A PKCS#12 works here directly; a JKS needs converting, which is a step for a human. Never copy the password
   into output.

6. **Hand over a draft** with the unmapped list and the verification steps from the shared rules.

## Output shape

- The `WsseMiddleware` construction, ready to paste, spelling out only what departs from the defaults.
- Each departure traced to the SoapUI field that caused it.
- Unmapped items, as questions.
- The verification steps, unedited.
