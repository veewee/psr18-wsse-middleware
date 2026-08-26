# Choosing parts and key references

[← Back to the deep dives](../README.md#deep-dives)

A few value objects let you say which parts to protect and how a token is referenced.

`Part` names the parts a block targets:

- `Part::body()`: the SOAP Body. Named by its position (`Envelope` then `Body`), not by its name alone, so a
  signed Body moved out of the envelope no longer answers for the empty slot a reader would look at.
- `Part::timestamp()`: the `wsu:Timestamp` in the Security header (add a `Timestamp` block to produce one).
- `Part::element(string $namespace, string $localName)`: a specific element by qualified name, wherever it sits
  in the message. There must be exactly one: two elements sharing the name make the part ambiguous, which is
  refused rather than resolved by picking one.
- `Part::path(QualifiedName ...$steps)`: an element by **where it sits** rather than only by what it is called.
  The steps run from the document element down and each must match exactly one direct child of the one before
  it, so an element carrying the same name elsewhere never satisfies it. Reach for this instead of
  `Part::element()` when your application reads the element at a fixed position:
  ```php
  use Soap\Psr18WsseMiddleware\Xml\QualifiedName;

  Part::path(
      new QualifiedName('http://www.w3.org/2003/05/soap-envelope', 'Envelope'),
      new QualifiedName('http://www.w3.org/2003/05/soap-envelope', 'Body'),
      new QualifiedName('urn:my-service', 'Order'),
  );
  ```
- `Part::byId(string $id)`: an element by its `wsu:Id`. Inbound this names an element but not a **position**: a
  signed element carrying that id satisfies the requirement wherever it now sits in the document, including
  somewhere your application never reads. Where that matters, use `Part::path()` instead, which binds the
  element to where a reader will look for it. `Part::body()` is a path for exactly this reason.
- `Part::usernameToken()` / `Part::binarySecurityToken()`. Shortcuts for the `wsse:UsernameToken` and
  `wsse:BinarySecurityToken` in the Security header (equivalent to `Part::element()` with the WS-Security namespace).

When a part is encrypted, it also carries **how** it is encrypted, and the two shortcuts differ on purpose:
`Part::body()` encrypts in `EncryptionMode::Content`, replacing the Body's children and leaving the Body element
itself in place, while every other part encrypts in `EncryptionMode::Element`, replacing the element whole.
Override it with `withEncryptionMode()` when a peer expects the other form:

```php
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptionMode;

Part::body()->withEncryptionMode(EncryptionMode::Element);
```

This only affects encryption. A signature covers the element either way, and the signing-only parts below carry
no mode at all.

Three **dynamic** parts are expanded against the live message rather than naming one element. They work in both
directions: outbound the Signature block signs every element they expand to; inbound `VerifySignature` requires
every such element to have been signed.

- `Part::securityHeaderContents()`: every element currently in the `wsse:Security` header (the Timestamp, any
  tokens; the `ds:Signature` itself is excluded). This is part of the signing default.
- `Part::soapHeaders()`: every SOAP header block **except** the `wsse:Security` header itself (for example
  WS-Addressing headers). Opt in with `withParts([Part::body(), Part::securityHeaderContents(), Part::soapHeaders()])`.

  It expands against the message **as it is when the signature is built**, so a header added afterwards is not
  covered. If you use it to sign WS-Addressing headers, `WsaMiddleware` has to run before `WsseMiddleware`, and
  in a `PluginClient` the request passes through the plugins in array order:

  ```php
  new PluginClient($client, [
      new WsaMiddleware(),      // adds wsa:To, wsa:Action, ... first
      new WsseMiddleware(...),  // then signs them
  ]);
  ```

  Listed the other way round the signature is built before the addressing headers exist, `Part::soapHeaders()`
  expands to nothing for them, and the message looks fully protected while `wsa:To` and `wsa:Action` are not
  covered at all.

- `Part::primarySignature()`: the one `ds:Signature` the Security header already carries, whole. This is what an
  endorsing supporting token covers, and it is the **only** way to cover a signature: the two parts above
  exclude every `ds:Signature` in both directions, because a signature is never one of the parts it covers and
  outbound it does not yet exist when the parts are resolved.

  Unlike the other two it refuses rather than expanding to what it finds. No signature in the header means the
  endorsing block was placed before the block it endorses, which would otherwise sign nothing; two mean neither
  is the primary one, and document order does not get to decide. See
  [Endorsing a signature](outbound-blocks.md#endorsing-a-signature-with-a-certificate-you-control).

`KeyRef` (for signing), and `EncKeyRef` (for encryption) choose how your certificate is referenced:

- `Outbound\KeyReference\KeyRef`: `BinarySecurityToken` (embed the token and point at it; the X.509 interop default for
  signing), `SubjectKeyIdentifier`, `IssuerSerial`, `Thumbprint`, `SamlAssertion` (point at the assertion an
  `Outbound\SamlAssertion` block placed in the header, for Holder-of-Key; see
  [the outbound blocks](outbound-blocks.md)).

  For a reference this package does not model, build the `KeyIdentifier` yourself and pass it with
  `Outbound\Signature::withKeyIdentifier()`, which overrides whatever the signing key resolved.
- `Outbound\KeyReference\EncKeyRef`: `SubjectKeyIdentifier` (the default for encryption), `IssuerSerial`, `Thumbprint`,
  `BinarySecurityToken`. It is passed to the [`WrappedSessionKey`](outbound-blocks.md#symmetric-key-sources)
  rather than to the `Encryption` block, because it says how the key's own recipient is named.

Two more reference types exist for a symmetric key, and neither names a certificate:

- `Outbound\KeyReference\EncryptedKeySha1KeyIdentifier`: the WSS 1.1 `EncryptedKeySHA1` form, carrying
  `base64(SHA-1(wrapped cipher bytes))`. It names the key itself rather than any element, so it stays valid
  however the key travels and across a correlated response. This is what a symmetric signature uses by default;
  `Keys\SymmetricKeyReference` on the key source chooses it.
- `Outbound\KeyReference\LocalTokenKeyIdentifier`: a `wsse:Reference URI="#..."` naming an element this same
  Security header carries, with no `ValueType`, because the referenced element says what it is. Used for a local
  `xenc:EncryptedKey` and for a local `wsc:DerivedKeyToken`. Every `xenc:EncryptedData` uses this form, which is
  what receivers read.

Inbound, both forms resolve against the keys the exchange established and against nothing else. A reference
naming a key this exchange never saw is refused rather than searched for; see
[Inbound blocks](inbound-blocks.md).

`KeyStore\TrustStore::fromCertificates(Certificate ...$anchors)` lists the certificates you trust when verifying a
response. Each entry may be a CA to chain up to, or the peer's own certificate, which is honoured as a direct
pin: the presented certificate must be that exact certificate, byte for byte. A pin is still checked for
validity and key usage, and pinning one certificate does not extend trust to anything its issuer signed.
`->withRevocationLists(CertificateRevocationList ...$lists)` additionally turns on fail-closed revocation
checking against lists you supply: see [Revocation checking](trust.md#revocation-checking-opt-in).

