---
name: wsse-import-wspolicy
description: Use when turning a WS-SecurityPolicy into php-soap/psr18-wsse-middleware wiring. Triggers on sp: assertions such as sp:AsymmetricBinding, sp:SymmetricBinding, sp:TransportBinding, sp:SignedParts, sp:EncryptedParts, sp:AlgorithmSuite, sp:X509Token, sp:Wss10 or sp:Wss11, on a wsp:Policy or wsp:PolicyReference in a WSDL, on a WebSphere policy set's policy.xml, and on requests like "here is their WSDL, what security do we need" or "port this security policy to PHP".
---

# Importing a WS-SecurityPolicy

The broadest of the import skills. WS-SecurityPolicy is an OASIS standard rather than one vendor's format, so
this covers Apache CXF and WSS4J, .NET and WCF, and WebSphere from version 7 onward. It is also the one that
usually needs no extra file: the policy is normally in, or referenced from, the WSDL you already have.

Two references, both required:

- [Shared import rules](../../references/wsse-import-rules.md): mirror or copy, the three rules, what to do with
  unmapped settings, and how the result gets verified.
- [The WS-SecurityPolicy assertions](references/ws-securitypolicy.md): the assertion vocabulary, the algorithm
  suite table, and the mapping for every assertion.

## Procedure

1. **Find the policy and follow the references.** Look for `wsp:Policy` in the WSDL, and for
   `wsp:PolicyReference` pointing at a `wsu:Id` elsewhere in the document or at an external URI. A WSDL that
   references a policy it does not contain is incomplete: ask for the rest rather than guessing at it.

2. **Pick one alternative, and say which.** `wsp:ExactlyOne` wrapping several `wsp:All` blocks means the service
   accepts any one of them, not all of them. Choosing is a judgement call, so state which alternative you took
   and why. Prefer the one whose algorithms are strongest, since that is the one least likely to need a downgrade.

3. **Read the attachment point, because it decides direction.** This is where WS-SecurityPolicy differs from the
   other formats: assertions inside the binding apply to both directions, while a policy attached to
   `wsdl:input` constrains the request (your `outbound`) and one attached to `wsdl:output` constrains the
   response (your `inbound`). Do not assume symmetry; check.

4. **Identify the binding first.** `sp:TransportBinding` means TLS does the protecting and you may need nothing
   but a `Timestamp` and perhaps a `Username`. `sp:AsymmetricBinding` is the case that maps onto signing and
   encryption blocks. `sp:SymmetricBinding` mostly does not map; see the reference.

5. **Expand `sp:AlgorithmSuite` from the table in the reference, never from the name.** The suite names mislead:
   the `Sha256` in `Basic256Sha256` is the digest, not the signature, and every standard suite specifies
   RSA-SHA1 for the signature and AES-CBC for the data. Expect two or three deliberate downgrades against our
   defaults, and treat each one under rule 2 of the shared rules.

6. **Map the tokens, the parts, then the references.** `sp:InitiatorToken` is your signing identity;
   `sp:RecipientToken` is the certificate you encrypt to. `sp:SignedParts` and `sp:EncryptedParts` give the part
   lists. The nested `sp:Require*Reference` assertions give the key reference.

7. **Hand over a draft** with the unmapped list and the verification steps from the shared rules. Name the policy
   alternative you chose at the top, so a reviewer can check that decision independently of the wiring.

## Output shape

- The `WsseMiddleware` construction, ready to paste, spelling out only what departs from the defaults.
- The chosen policy alternative, named.
- Each departure traced to the assertion that caused it, algorithm downgrades especially.
- Unmapped items, as questions.
- The verification steps, unedited.
