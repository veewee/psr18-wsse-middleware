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

Two **dynamic** parts are expanded against the live message rather than naming one element. They work in both
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

`KeyRef` (for signing), and `EncKeyRef` (for encryption) choose how your certificate is referenced:

- `Outbound\KeyReference\KeyRef`: `BinarySecurityToken` (embed the token and point at it; the X.509 interop default for
  signing), `SubjectKeyIdentifier`, `IssuerSerial`, `Thumbprint`, `SamlAssertion` (point at the assertion an
  `Outbound\SamlAssertion` block placed in the header, for Holder-of-Key; see
  [the outbound blocks](outbound-blocks.md)).

  For a reference this package does not model, build the `KeyIdentifier` yourself and pass it with
  `Outbound\Signature::withKeyIdentifier()`, which overrides `keyRef`.
- `Outbound\KeyReference\EncKeyRef`: `SubjectKeyIdentifier` (the default for encryption), `IssuerSerial`, `Thumbprint`,
  `BinarySecurityToken`.

`KeyStore\TrustStore::fromCertificates(Certificate ...$anchors)` lists the certificates you trust when verifying a
response. Each entry may be a CA to chain up to, or the peer's own certificate, which is honoured as a direct
pin: the presented certificate must be that exact certificate, byte for byte. A pin is still checked for
validity and key usage, and pinning one certificate does not extend trust to anything its issuer signed.
`->withRevocationLists(CertificateRevocationList ...$lists)` additionally turns on fail-closed revocation
checking against lists you supply: see [Revocation checking](trust.md#revocation-checking-opt-in).

