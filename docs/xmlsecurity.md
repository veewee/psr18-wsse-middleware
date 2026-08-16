# The XML-Security layer

[← Back to the deep dives](../README.md#deep-dives)

`Soap\Psr18WsseMiddleware\XmlSecurity\` is what the signing, encryption, decryption and verification blocks
are built on. **You do not need this page to use the middleware.** Read it to swap one of those services out,
or to drive the layer on plain XML that is not a SOAP message.

## Custom engine services

The signing, encryption, decryption and verification blocks build the engine service they need with secure
defaults, so you normally pass nothing extra. To customize one, override the bundled service
with a `with*()` method:

- `Outbound\Signature::withSigner(XmlSigner $signer)`
- `Outbound\Encryption::withEncryptor(XmlEncryptor $encryptor)`
- `Inbound\Decrypt::withDecryptor(XmlDecryptor $decryptor)`
- `Inbound\VerifySignature::withVerifier(XmlSignatureVerifier $verifier)`

```php
(new Outbound\Signature($clientCertificate))->withSigner($customSigner);
(new Inbound\Decrypt($privateKey))->withDecryptor($customDecryptor);
```

Reach for this only when the defaults genuinely do not fit.

Every engine class that gates an algorithm takes its `CryptoPolicy` as a required argument rather than falling
back to `CryptoPolicy::default()`. If you drive the layer directly, pass the policy you configured on every
call: a deployment that hardened its allow-lists and then silently got the library defaults would accept
parameterizations it had explicitly refused.

## Driving the layer without SOAP

**Skip this unless you want to sign, verify, encrypt or decrypt plain XML that is not a SOAP message.** Using the
middleware, none of it applies: the blocks wire it up for you.

The XML-Security layer never looks for a `wsse:Security` header. It is given
the element to work against, so it can be driven on any XML document, and the WS-Security blocks are the only
part of this package that knows what a SOAP envelope is.

- **The container is an input, not something searched for.** `SigningRequest` and `EncryptionRequest` take a
  `Dom\Element $container` as their first argument: the element the `ds:Signature` / `xenc:EncryptedKey` is
  appended to. The blocks pass their `wsse:Security` header.
- **Which `ds:KeyInfo` shapes are understood is an input as well.** Standalone, the layer reads the plain
  XML-DSig form. An inline `ds:X509Certificate`. The WS-Security token forms (a `wsse:BinarySecurityToken`
  reference, a `wsse:KeyIdentifier`, an issuer and serial) come from the profile, so pass its resolver to read
  them outside the middleware:
  ```php
  use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseKeyInfoResolver;

  Verifier::create($ids->lookup(), new WsseKeyInfoResolver());
  ```
- **The scope is an input too, on the read side.** `XmlSignatureVerifier::verify()` takes the element whose
  signature is being verified, and `DecryptionRequest` names the container the `xenc:EncryptedKey` and
  `xenc:ReferenceList` are read from. Neither is defaulted, because a default would mean "search the whole
  document": which is what lets an element planted elsewhere be mistaken for the real one. Anyone can wrap a
  session key to a public certificate, so on the decryption side this is what distinguishes a key meant for this
  recipient from one an injector supplied.

```php
public function sign(Document $document, SigningRequest $request): void;
public function encrypt(Document $document, EncryptionRequest $request): void;
public function verify(Document $document, VerificationPolicy $policy, Element $scope): VerifiedSignature;
public function decrypt(Document $document, DecryptionRequest $request): void;
```

### Enveloped signatures (layer level only)

The verifier accepts the `enveloped-signature` transform, so it can verify a signature that lives *inside* the
element it signs. The standard shape for a plain signed XML document, and the shape a signed SAML assertion
arrives in. A reference may declare the transform on its own, or followed by one canonicalization; the order is
enforced, and every canonicalization is still allow-list checked exactly as elsewhere.

Reach it by naming the signed element as the scope:

```php
$verified = Verifier::create()->verify($document, $policy, $signedElement);
```

**No WS-Security block uses this.** `Inbound\VerifySignature` scopes to the `wsse:Security` header addressed to
you, and a signature is only recognised as that scope's own when it is a *direct child* of it. A signature
nested deeper is never mistaken for it, which is deliberate XML Signature Wrapping hardening. So an assertion's
own signature is not verified by that block, and this is a layer-level capability for a standalone caller.

That is not a gap in message security: when a WSSE signature covers an assertion, its digest already covers the
assertion *together with* the signature embedded in it, so tampering is caught without this transform. What the
transform adds is authenticating the issuer's signature on the token, which a SOAP client normally does not do:
it presents an assertion obtained from an STS, and the service verifies the issuer.

Two rules make it safe to accept at all, and both refuse rather than guess:

- The element must contain **exactly one** `ds:Signature`, and it must be the signature being verified, compared
  by object identity. Stripping every signature under the element would let an injected second one be dropped
  from the digest silently.
- An element containing **no** signature is refused too: the transform claims self-exclusion while the signature
  sits elsewhere, which is a relocated signature claiming to cover something it is not inside.

The exclusion is applied as a node-set filter while canonicalizing in place. The signature is never detached or
cloned away, because a detached clone loses the namespace declarations it inherits from its ancestors and the
canonical bytes would no longer match what the signer computed.

### Id conventions

The layer references what it signs and encrypts by id, and does not hard-code which attribute carries it. It
ships the W3C `xml:id`, so driving it directly needs no configuration:

```php
Signer::create();      // xml:id
Verifier::create();     // xml:id
```

The WS-Security blocks need `wsu:Id` instead, as the profile mandates, and set that up themselves. Nothing to
configure when you use the middleware. To drive the layer standalone under that convention, or under one of
your own:

```php
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\AttributeIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdAttribute;

$ids = new WsuIdConvention();                                          // wsu:Id
$ids = new AttributeIdConvention(IdAttribute::of('urn:my:ns', 'my:Id'));  // your own

Signer::create($ids);
Encryptor::create($ids);
Verifier::create($ids->lookup());     // verifying only ever resolves ids
Decryptor::create($ids->lookup());
```

Sign and verify with the same convention or the references will not resolve. Handing over the pair is what makes
that hard to get wrong; `XmlSecurity\IdConvention` documents the rest.
