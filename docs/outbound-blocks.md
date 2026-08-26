# Outbound blocks

[← Back to the deep dives](../README.md#deep-dives)

The blocks that secure the request you send. Every block is a small, immutable value object you drop
into the `outbound` list: a short example, then every constructor argument and fluent method with its
default and what it expects.

See [Inbound blocks](inbound-blocks.md) for their response-side counterparts, and the
[README](../README.md#the-building-blocks) for the order to list them in.

Two blocks take a credential object rather than a bare certificate: `Signature` takes a **signing key** and
`Encryption` takes a **symmetric key source**. [Signing keys](#signing-keys) and
[Symmetric key sources](#symmetric-key-sources) below describe them, and they are worth reading before the
blocks that consume them.

## Outbound: `Timestamp`

Stamps the message with a created/expires window so the receiver can reject a stale or replayed call. It writes
a `wsu:Timestamp` carrying `wsu:Created` (now, UTC), and `wsu:Expires` (now + ttl), and mints a `wsu:Id` on it so
a later `Signature` block can sign the timestamp by reference.

```php
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

new Outbound\Timestamp();        // expires timestampTtl seconds from now (300 by default)
new Outbound\Timestamp(60);      // expires 60 seconds from now
```

- `?int $ttl = null`: seconds from now until the message's `Expires`. Must be a positive integer. `null`, the
  default, takes the window from the profile's `timestampTtl`, so narrowing it there narrows both directions.
  Pick a value that comfortably covers your round trip plus the receiver's clock skew.

## Outbound: `Username`

Adds a `wsse:UsernameToken` carrying the caller's credentials. It supports three modes: username only, username
with a plaintext password, and username with a digested password.

```php
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

// Username only:
new Outbound\Username('your-user');

// Plaintext password (only safe over TLS):
new Outbound\Username('your-user', 'your-password');

// Digested password:
new Outbound\Username('your-user', 'your-password', digest: true);

// Same, fluently:
(new Outbound\Username('your-user'))
    ->withPassword('your-password')
    ->withDigest(true);

// Plaintext password with replay markers, for peers that require them:
(new Outbound\Username('your-user', 'your-password'))
    ->withNonce(true)
    ->withCreated(true);
```

- `string $username`: the username sent in `wsse:Username`. Required.
- `?string $password = null`: the password. Default `null`, which sends a username-only token (no
  `wsse:Password`). Provide a value to send a password.
- `bool $digest = false`: how the password is sent. `false` (default) sends `PasswordText`, **the password in
  the clear**. Nothing here enforces TLS, so on a plain HTTP transport this puts your credentials on the wire
  for anyone on the path; use it only over TLS, and prefer `digest: true` where the service accepts it. `true` sends
  `PasswordDigest`: `Base64(SHA1(nonce + created + password))`, with a fresh `wsse:Nonce` and `wsu:Created`, so
  the password never travels in the clear. Digest mode requires a password; combining `digest: true` with no
  password throws.
- `withPassword(string $password): self` returns a copy with the password set.
- `withDigest(bool $digest): self` returns a copy with the digest flag set.
- `withNonce(bool $nonce): self` returns a copy that emits a fresh `wsse:Nonce`, `false` by default. Use it when
  a peer wants a replay marker alongside a `PasswordText` (or password-less) token. Digest mode emits the nonce
  regardless: the digest is computed over it, so a token without it could not be verified.
- `withCreated(bool $created): self` returns a copy that emits a `wsu:Created`, `false` by default, with the same
  digest-mode note. It carries the token's creation instant, which lets a receiver age out replays.

## Outbound: `BinarySecurityToken`

Attaches your X.509 certificate as a `wsse:BinarySecurityToken` (base64-DER), so the receiver has the public key
it needs to verify your signature. A `wsu:Id` is minted on the token so a direct reference can point at it.

```php
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

new Outbound\BinarySecurityToken(Certificate::fromFile('security_token.pub'));
```

- `Certificate $certificate`: the public X.509 certificate to embed, as a `KeyStore\Certificate`. Required.

You rarely add this block by hand: the `Signature` block embeds one automatically when you reference the key by
`KeyRef::BinarySecurityToken`. Add it explicitly only when a server expects the token present on its own.

- `BinarySecurityToken::forCertificatePath(CertificateChain $path): self`: a named constructor embedding the
  whole certification path as a `#X509PKIPathv1` token instead of the leaf alone. Signing with a path is
  configured on the [`CertificateSigningKey`](#signing-keys) you hand the `Signature` block; reach for this
  constructor only when the token has to stand on its own.

## Signing keys

A `Signature` block takes a `SigningKey`, which says how the signature is keyed and how its `ds:KeyInfo` points
at that key. There are two, because WS-Security defines two kinds of signature.

```php
use Soap\Psr18WsseMiddleware\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\KeyRef;

// Signed with a private key, advertised through a certificate. The ordinary X.509 case.
new Outbound\CertificateSigningKey($clientCertificate, KeyRef::BinarySecurityToken);

// Keyed by a symmetric secret: a MAC rather than a signature. See Symmetric key sources below.
new Outbound\SymmetricSigningKey($sessionKeySource);
```

### `CertificateSigningKey`

- `ClientCertificate $certificate`: the certificate-and-key bundle to sign with. The private key signs; the
  public certificate is advertised in `ds:KeyInfo`. Required.
- `KeyRef $keyRef = KeyRef::BinarySecurityToken`: how the certificate is referenced. Default
  `KeyRef::BinarySecurityToken`, the X.509 direct-reference interop default: a `wsse:BinarySecurityToken` is
  embedded and the signature points at it by `wsu:Id`. The other cases (`SubjectKeyIdentifier`, `IssuerSerial`,
  `Thumbprint`, `SamlAssertion`) put an inline reference derived from the certificate and embed no token. See
  [Choosing parts and key references](parts-and-key-references.md).
- `?CertificateChain $path = null`: send your whole certificate chain in the token (a `#X509PKIPathv1`
  `wsse:BinarySecurityToken`) instead of the leaf certificate alone. `null` by default. Pass one for a server
  that will not complete the chain from its own store and needs the intermediates handed to it:
  ```php
  use Soap\Psr18WsseMiddleware\KeyStore\Pkcs12Bundle;

  $bundle = Pkcs12Bundle::fromFile('client.p12', 'xxx');

  new Outbound\Signature(new Outbound\CertificateSigningKey(
      ClientCertificate::fromPkcs12($bundle),
      path: $bundle->chain,
  ));
  ```
  A `.p12` already contains the chain, which is where it usually comes from; a PEM signing identity has none to
  offer. The chain must start with the certificate you sign with, and `keyRef` must be
  `KeyRef::BinarySecurityToken`, or the constructor throws.

Pairing this with an HMAC signature method throws: keying a MAC with a certificate makes the "secret" the peer's
public key bytes, which anyone holding the certificate has.

### `SymmetricSigningKey`

- `SymmetricKeySource $source`: where the secret comes from. Required. Passing the same source to an
  `Encryption` block is what makes the two share one key.

The signature method has to be one of the HMAC ones; an asymmetric method throws, because a symmetric secret
cannot provide private key material. The block asks the source for the digest-length key its method prefers, and
a source already carrying a key of another width still serves it: HMAC pads a short key and hashes a long one, so
any length works.

**A shared key's width is the MAC's real strength, whatever the method is called.** Pair `HMAC_SHA256` with a key
source minted for AES-128 and the MAC is keyed with 16 bytes, not the 32 its name implies. That is not a defect
and nothing refuses it, because refusing would mean a cipher and a MAC could never share a key at all; it is
simply worth knowing before you read the method name as a strength. Give each a
[derived key](#derivedsessionkey) of its own, or state the width you want on the
[key source](#wrappedsessionkey), when the two disagree and you care.

## Symmetric key sources

An `Encryption` block, and a `SymmetricSigningKey`, take a `SymmetricKeySource`: a recipe saying where a
symmetric key comes from and how a `ds:KeyInfo` names it. Three of them ship.

A source holds no key. It is constructed once with the middleware and reused for every message, and the key it
produces lives for exactly one request/response exchange. **Two blocks share one key by being handed the same
source object**, which is why a policy asking for a signature and an encryption keyed off one
`xenc:EncryptedKey` needs no keyword: you pass the same object twice.

```php
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\EncKeyRef;

$recipient = Certificate::fromFile('service.pub');

// A fresh key per exchange, carried to the recipient in an xenc:EncryptedKey.
new Keys\WrappedSessionKey($recipient, EncKeyRef::Thumbprint);

// A key derived from another one with P_SHA1, carried as a wsc:DerivedKeyToken.
new Keys\DerivedSessionKey(new Keys\WrappedSessionKey($recipient));

// A secret both sides already hold. Nothing is written to the message.
new Keys\PreSharedSessionKey($secret, 'the-agreed-name', 'urn:example:pre-shared-key');
```

### `WrappedSessionKey`

Mints a session key and carries it to the recipient wrapped under its public certificate, as an
`xenc:EncryptedKey` in the Security header. The ordinary way to key a symmetric binding when the two sides share
no secret.

- `Certificate $recipient`: the recipient's public certificate, used to wrap the key. Required.
- `EncKeyRef $keyRef = EncKeyRef::SubjectKeyIdentifier`: how the recipient's certificate is referenced inside
  the `xenc:EncryptedKey`, so it knows which private key unwraps the session key. The other cases are
  `IssuerSerial`, `Thumbprint` and `BinarySecurityToken`.
- `?DataEncryptionMethod $keyLength = null`: fixes the key's width up front. `null`, the default, takes the
  width from the first block that asks for the key. State it when your blocks disagree: the wrapped bytes are
  fixed once written, so a later block needing a different exact width is refused rather than served a key its
  cipher cannot use.
Every consumer of the key names it by the WSS 1.1 `EncryptedKeySHA1` identifier, which names the key itself
rather than the element carrying it. Naming the element is representable in the format and is not offered here:
an `xenc:EncryptedData` naming its key that way is one WSS4J cannot resolve, so the option would work for a
signature and not for an encryption. Inbound, both forms are accepted, because which one a peer echoes is not
something a client gets to constrain.
- `?KeyTransportAlgorithm $keyTransportAlgorithm = null`: the whole key-transport choice (method plus OAEP hash)
  in one atomic value, so an invalid pairing cannot be expressed. `null` takes it from the profile. See
  [Security profile and defaults](security-profile.md).
- `?ExternalParts $optimizedCipherBytes = null`: write the wrapped key into a MIME part and leave an
  `xop:Include` where its `xenc:CipherValue` would have been. Pass the same registration you gave
  `Encryption::withOptimizedCipherBytes()` when both values should travel that way; whether an element's cipher
  value is optimized is decided per element, so the key and the content are separate choices.

**A request protected only by a `WrappedSessionKey` signature authenticates nobody.** The key was minted here
and encrypted under the server's public certificate, which anyone holding that certificate can do, so the
signature proves possession of no credential. Pair it with an
[endorsing signature](#endorsing-a-signature-with-a-certificate-you-control) over a certificate you control when
the request has to authenticate its sender. A real `sp:SymmetricBinding` policy nearly always does. The response
direction differs: a symmetric signature on a response does authenticate the server, because only its private
key could have unwrapped the key.

### `DerivedSessionKey`

Derives a key from another source with P_SHA1 and carries it as a `wsc:DerivedKeyToken`. This is what a policy
asking for `sp:RequireDerivedKeys` wants: the shared token is never used to sign or encrypt directly, and each
use gets a key of its own.

- `SymmetricKeySource $from`: the source to derive from. Required. Deriving from another `DerivedSessionKey`
  throws: no peer emits chained derivation.
- `?string $label = null`: the derivation label. `null` uses the specification's own default, which is what
  every peer emitting this shape uses.
- `int $offset = 0`: how far into the derived stream this key starts, for a peer that partitions one stream
  across several keys.

There is no length argument: the consuming block's algorithm defines it, and it arrives with the request. Give
each block a derived key of its own, which is also what makes the two derive to different keys:

```php
$shared = new Keys\WrappedSessionKey($recipient);

new WsseMiddleware($profile, outbound: [
    new Outbound\Timestamp(),
    (new Outbound\Signature(new Outbound\SymmetricSigningKey(new Keys\DerivedSessionKey($shared))))
        ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
        ->withParts([Part::body(), Part::timestamp()]),
    (new Outbound\Encryption(new Keys\DerivedSessionKey($shared)))
        ->withDataEncryptionMethod(DataEncryptionMethod::AES128_GCM)
        ->withParts([Part::body()]),
]);
```

One `xenc:EncryptedKey` and two `wsc:DerivedKeyToken` come out of that, the first thirty-two bytes wide because
the MAC is SHA-256 and the second sixteen because the cipher is AES-128. Neither number is written anywhere.

Every token carries a fresh nonce, because a repeated nonce repeats the derived key and two messages would then
share one MAC key. Which WS-SecureConversation dialect the token is written in comes from the profile; see
[Security profile and defaults](security-profile.md).

### `PreSharedSessionKey`

A secret both sides already hold, named by an identifier they agreed on out of band. Nothing is written to the
message.

- `SessionKey $secret`: the shared secret. Required, non-empty. See [Key stores](key-stores.md#session-keys) for
  where one comes from.
- `string $identifier`: the name both sides agreed on. Carried verbatim as the `wsse:KeyIdentifier` content, and
  matched verbatim against what an inbound reference names.
- `string $valueType`: the `ValueType` URI the agreed reference declares.
- `string $encodingType = ...Base64Binary`: the encoding the identifier is written in.

Unlike a wrapped session key this **does** authenticate, and mutually: only the two holders of the secret can
produce a MAC that verifies under it. It is not non-repudiable, because either of them could have produced any
given message.

**Which value type to agree on depends on the peer.** A WSS4J or CXF one wants the WSS 1.1 `EncryptedKeySHA1`
URI, because that is the only custom identifier its emitter writes for a shared secret. Nothing here is a digest
of any cipher bytes and it does not have to be: the URI names the shape of the reference rather than how the
value was arrived at. Passing that URI also makes the reference carry the `wsse11:TokenType` the profile
requires alongside it, which a receiver enforcing the Basic Security Profile refuses a reference for lacking.
Their reader is the tolerant half and takes any type at all, so a peer that is something else is free to agree
on another.

The inbound blocks need this source handed to them, because no outbound direction established it; see
[Inbound blocks](inbound-blocks.md).

## Outbound: `Signature`

Adds a detached, multi-reference `ds:Signature` to the Security header. You choose the
[signing key](#signing-keys), which parts are signed, and the algorithms.

```php
use Soap\Psr18WsseMiddleware\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\KeyRef;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;

$clientCertificate = ClientCertificate::fromFile('client.pem')->withPassphrase('xxx');

// Default: sign the Body and everything in the Security header, reference the key via an embedded
// BinarySecurityToken.
new Outbound\Signature(new Outbound\CertificateSigningKey($clientCertificate));

// Sign only the body, reference by Subject Key Identifier:
(new Outbound\Signature(new Outbound\CertificateSigningKey($clientCertificate, KeyRef::SubjectKeyIdentifier)))
    ->withParts([Part::body()]);
```

- `SigningKey $signingKey`: how the signature is keyed and referenced. Required. See
  [Signing keys](#signing-keys) for the two implementations and their own arguments.
- `withKeyIdentifier(KeyIdentifier $keyIdentifier): self`: replace the reference the signing key resolved with
  one you built, for a `ValueType` this package does not model. It is orthogonal to where the key came from, so
  it works for a symmetric signature too.
- `withAttachments(ExternalParts $attachments): self`: also cover the message's attachments, in the same
  `ds:Signature` as the in-document parts. Off by default. Pass
  `AttachmentParts::request($attachmentStorage, ExternalPartCoverage::Complete)`; see [Attachment security](attachments.md).
  ```php
  use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\AttachmentParts;
  use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartCoverage;

  (new Outbound\Signature(new Outbound\CertificateSigningKey($clientCertificate)))
      ->withAttachments(AttachmentParts::request($attachmentStorage, ExternalPartCoverage::Complete));
  ```
  The second argument says how much of each part the signature covers: `ExternalPartCoverage::Content` for the
  content alone, `Complete` to cover the canonical MIME header block as well. It is required, with no default,
  because the peer's policy decides it and both wrong answers are refused by that peer. A bare
  `<sp:Attachments/>` means `Complete`; the
  [configuration table](attachments.md#how-much-of-a-part-a-protection-covers) is the whole rule.
  Adds coverage rather than replacing it: an attachment reference sits alongside whatever `withParts()` asks
  for. What gets digested depends on the media type: XML is canonicalized, other text has its line endings
  normalized, and everything else is digested as it travels; see [Attachment security](attachments.md).
**A signed element may not stand in for content the signature leaves out.** An `xop:Include` in a signed
element is a pointer: digesting the element covers the reference while the bytes it names travel in their own
MIME part, and the message still satisfies a far-side policy check for that element being signed. So an
include under a signing target is accepted only when the reference it names is one of the attachments this
same signature covers, which is the ordinary MTOM shape. Otherwise the signature is refused before it is made.
Register the attachment with `withAttachments()` and both the pointer and the bytes are protected.

- `withParts(list<Part> $parts): self`: which parts to sign. Default is `[Part::body(),
  Part::securityHeaderContents()]`: the Body plus every element currently in the Security header (the Timestamp,
  any tokens), resolved at send time. Because it signs whatever is present, the default never fails when a part
  is absent. Must be a non-empty list of `Part` descriptors. See
  [Choosing parts and key references](parts-and-key-references.md) for the dynamic parts and shortcuts. An
  empty list throws: it is not read as "the default", because a signature covering nothing verifies against any
  trusted key while protecting no part of the message.
- `withSignatureMethod(SignatureMethod $method): self`: the signature algorithm. Default: the profile's
  `signatureMethod()` (RSA-SHA256). RSA and ECDSA are both supported. Pick an ECDSA method when your signing
  identity is an EC certificate and key:
  ```php
  use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;

  (new Outbound\Signature(new Outbound\CertificateSigningKey($clientCertificate)))
      ->withSignatureMethod(SignatureMethod::ECDSA_SHA256);
  ```
  The ECDSA cases are `ECDSA_SHA256`, `ECDSA_SHA384` and `ECDSA_SHA512` (the xmldsig-more URIs). They require an
  EC certificate and key; an RSA key paired with an ECDSA method will not sign. The RSA cases stay `RSA_SHA256`
  (the default), `RSA_SHA384` and `RSA_SHA512`.

  Two legacy cases exist and are **not** accepted inbound by default: `RSA_SHA1` and `DSA_SHA1` (which needs a
  DSA key to sign with). Use either only for a peer that requires it, and add it to `acceptedSignatureMethods`
  to verify one (see [Security profile and defaults](security-profile.md)).

  The `HMAC_SHA256`, `HMAC_SHA384` and `HMAC_SHA512` cases are keyed by a symmetric secret rather than by a
  certificate, and need a [`SymmetricSigningKey`](#signing-keys). They follow the same rule their RSA
  counterparts do: the SHA-2 sizes are accepted inbound by default and the SHA-1 one (`HMAC_SHA1`, plus
  `HMAC_SHA224`) is named deliberately or not at all.
- `withDigestMethod(DigestMethod $method): self`: the per-reference digest algorithm. Default: the profile's
  `digestMethod()` (SHA-256). `SHA384` and `SHA512` are also accepted inbound by default. `SHA1` and
  `RIPEMD160` are available but not accepted inbound by default; add them to `acceptedDigestMethods` only for a
  peer that requires them.
- `withCanonicalization(SignatureCanonicalization $canonicalization): self`: the canonicalization method.
  Default: the profile's `canonicalization()` (exclusive C14N). The exclusive variants (`EXC_C14N`,
  `EXC_C14N_COMMENTS`) are the WSSE norm. The inclusive Canonical XML 1.0 variants (`C14N`, `C14N_COMMENTS`)
  are also available for a server that requires them:
  ```php
  use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;

  (new Outbound\Signature(new Outbound\CertificateSigningKey($clientCertificate)))
      ->withCanonicalization(SignatureCanonicalization::C14N);
  ```
  If you sign with an inclusive variant and also verify the response with one, add it to the profile's
  `acceptedCanonicalizations` allow-list as well (see [Security profile and defaults](security-profile.md));
  by default only the exclusive variants are accepted inbound.
- `withInclusivePrefixes(): self`: pin the namespace prefixes an exclusive canonicalization would otherwise
  drop, as an `ec:InclusiveNamespaces PrefixList`. Off by default.

  Turn it on when a server rejects your signature as invalid even though everything else matches: some peers
  need a namespace declaration your message inherits from an ancestor, and exclusive canonicalization does not
  carry those unless they are pinned.
  ```php
  (new Outbound\Signature(new Outbound\CertificateSigningKey($clientCertificate)))
      ->withInclusivePrefixes();
  ```
  Nothing else changes: the list is worked out per element for you, and the receiver reads it from the signature.
  It has no effect on an inclusive canonicalization.

## Outbound: `Encryption`

Encrypts the requested parts of the message via XML-Enc, under a key a
[symmetric key source](#symmetric-key-sources) provides. Place it **after** `Signature` (sign-then-encrypt).

```php
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\EncKeyRef;

$recipient = Certificate::fromFile('service.pub');

// Default: encrypt the Body under a fresh session key, reference the recipient by Subject Key Identifier.
new Outbound\Encryption(new Keys\WrappedSessionKey($recipient));

// Reference the recipient by IssuerSerial:
new Outbound\Encryption(new Keys\WrappedSessionKey($recipient, EncKeyRef::IssuerSerial));
```

- `SymmetricKeySource $key`: where the session key comes from. Required. See
  [Symmetric key sources](#symmetric-key-sources). The block asks for exactly the width its data-encryption
  method takes, and a source already carrying a key of a different width is refused rather than serving one the
  cipher cannot use.

Where the `xenc:ReferenceList` goes follows from whether the key is shared, and you never state it:

- **Alone with its key**, this block nests the list inside the `xenc:EncryptedKey` and says nothing on the
  `xenc:EncryptedData`. The nesting already ties the key to the parts, and this is the shape every stack has
  always read.
- **Sharing its key** with another block, it cannot: the key is written when it is minted, before either block
  has said what it will cover, so the other block may already have signed the element carrying it. The list
  stands beside the key instead, and each `xenc:EncryptedData` names the key with a WSS 1.1 `EncryptedKeySHA1`
  identifier.

Both are what WSS4J emits, and its reader requires the matching pair: with the list detached it refuses a
message whose `xenc:EncryptedData` says nothing about its key, and with the list nested it refuses one that
does.
- `withParts(list<Part> $parts): self`: which parts to encrypt. Default is `[Part::body()]`. An empty list
  throws unless attachments are registered: it is not read as "the default". Encrypting nothing still wraps a
  session key and appends an `xenc:EncryptedKey`, so the Body would leave in cleartext under a message that
  reads as encrypted in every log and packet capture of it. An empty list is allowed when attachments are
  registered, because encrypting only the attachments is a real configuration. The check runs when the block
  runs, not when either method is called, so the order you chain them in does not matter.
- `withAttachments(ExternalParts $attachments): self`: also encrypt the message's attachments, under the same
  session key and in the same `xenc:EncryptedKey`. Off by default. Pass
  `AttachmentParts::request($attachmentStorage, ExternalPartCoverage::Content)`; see [Attachment security](attachments.md).
  ```php
  use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\AttachmentParts;
  use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartCoverage;

  (new Outbound\Encryption(new Keys\WrappedSessionKey($recipient)))
      ->withAttachments(AttachmentParts::request($attachmentStorage, ExternalPartCoverage::Content));
  ```
  This block emits content-only ciphertext, so an adapter built with `ExternalPartCoverage::Complete` is
  refused. No policy can require the wider one: a peer validates the coverage of a signature and never of an
  encryption.
  Each sealed part's `Content-Type` becomes `application/octet-stream` and its original media type is recorded
  on the `xenc:EncryptedData`, so the far side can restore it. An element whose content is or contains an
  `xop:Include` cannot be encrypted at all: that would protect the pointer while the bytes travel in the clear.
  Encrypt the attachment instead.
- `withOptimizedCipherBytes(ExternalParts $carriers): self`: write each cipher value's bytes into a MIME
  part of its own and leave an `xop:Include` in the `xenc:CipherValue`, instead of base64 in the document.
  Off by default.
  ```php
  use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\AttachmentParts;
  use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartCoverage;

  (new Outbound\Encryption(new Keys\WrappedSessionKey($recipient)))
      ->withOptimizedCipherBytes(AttachmentParts::request($attachmentStorage, ExternalPartCoverage::Content));
  ```
  This is WSS4J's `storeBytesInAttachment`. It buys the 33% that base64 costs, which is worth having on large
  payloads and nothing on small ones, and **no policy assertion can require it of either side**. It is
  supported because a WSS4J or CXF peer reads this shape whatever its own configuration says: resolving a
  cipher value's pointer is not something those peers made optional.

  This moves the encrypted **content**. The wrapped key in the header is written by the
  [key source](#symmetric-key-sources), so it moves when you give that source the same registration:

  ```php
  $carriers = AttachmentParts::request($attachmentStorage, ExternalPartCoverage::Content);

  (new Outbound\Encryption(new Keys\WrappedSessionKey($recipient, optimizedCipherBytes: $carriers)))
      ->withOptimizedCipherBytes($carriers);
  ```

  Two registrations rather than one because whether a cipher value is optimized is decided per element, and the
  two elements have different authors. Each minted part carries `Content-Type: application/ciphervalue` and the
  raw bytes, not base64.

  Two consequences worth knowing before you turn it on. The request becomes a multipart one, so the
  attachments middleware has to be in the pipeline, and under MTOM that means a SOAP 1.2 envelope. And it
  cannot be combined with encrypt-then-sign: the minted parts are not registered on the signing block, so
  signing an element that now holds a pointer is refused. WSS4J silently disables the option in that case; we
  do not, because a security-relevant setting that turns itself off leaves nothing downstream able to tell.
- `withDataEncryptionMethod(DataEncryptionMethod $method): self`: the bulk-data cipher. Default: the profile's
  `dataEncryptionMethod()` (AES-256-GCM).
How the session key reaches the recipient is the key source's business, so the key transport is configured
there rather than on this block. The default is RSA-OAEP with SHA-1. The label hash is what the previous
releases used, but the `Algorithm` URI is not: the default moved from `xmlenc#rsa-oaep-mgf1p` to
`xenc11#rsa-oaep`. A peer that pins the old URI needs `KeyTransportAlgorithm::legacyMgf1p()`:

```php
use Soap\Psr18WsseMiddleware\Algorithm\KeyTransportAlgorithm;

new Outbound\Encryption(new Keys\WrappedSessionKey(
    $recipient,
    keyTransportAlgorithm: KeyTransportAlgorithm::oaepSha256(),
));
```

The named constructors are `KeyTransportAlgorithm::oaepSha1()` (the default), `oaepSha256()`, `legacyMgf1p()`
(RSA-OAEP-MGF1P, SHA-1), and `rsa1_5()` (RSA-1_5, rejected inbound by default). Setting the profile's
`keyEncryptionMethod` and `oaepHash` moves the default for every source that states none.

### Endorsing a signature with a certificate you control

An endorsing supporting token is a second `Signature` block covering the whole primary `ds:Signature`. It is
what makes a request protected by a `WrappedSessionKey` authenticate anybody: the session key proves possession
of nothing, and this is where a certificate you control contributes.

```php
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\KeyRef;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;

$sessionKey = new Keys\WrappedSessionKey($recipient);

new WsseMiddleware($profile, outbound: [
    new Outbound\Timestamp(),
    (new Outbound\Signature(new Outbound\SymmetricSigningKey($sessionKey)))
        ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
        ->withParts([Part::body(), Part::timestamp()]),
    (new Outbound\Encryption($sessionKey))
        ->withParts([Part::body()]),
    (new Outbound\Signature(new Outbound\CertificateSigningKey($clientCertificate, KeyRef::Thumbprint)))
        ->withParts([Part::primarySignature()]),
]);
```

Order matters: the endorsing block goes **after** the block it endorses, and a block placed before it throws
rather than signing nothing. Two signatures already in the header means neither is the primary one, and that
throws too: which of them a reader treats as primary is not something document order decides.

`Part::primarySignature()` is the only way to cover a signature. `Part::securityHeaderContents()` deliberately
excludes every `ds:Signature` in both directions, because a signature is never one of the parts it covers and
outbound it does not yet exist when the parts are resolved.

An endorsed message a peer sends you verifies too. `Inbound\VerifySignature` checks **every** `ds:Signature`
directly inside the header it scopes to and requires each of them to verify, so what you may require is the union
of what they covered. A second signature is one more thing that must hold rather than an alternative the
verifier may pick, which is what makes an injected one refuse the message.

`Part::primarySignature()` is outbound only, though. Required inbound it refuses an endorsed message, because
such a message carries two signatures and which of them is primary is not something document order decides on a
message a peer shaped. **To require that a response was endorsed at all, register an identity check**: a
signature keyed by a shared secret names nobody, so `onTrustedSigner` has a signer to run against only when a
certificate also signed.

## Outbound: `SamlAssertion`

Imports a SAML 1.1 or 2.0 assertion you already obtained (from an STS) into the Security header. The assertion
string is parsed in isolation with DOCTYPE declarations rejected, and only the parsed nodes are adopted, so a
malicious assertion string cannot inject content. The assertion is imported verbatim, including any signature it
already carries.

```php
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

new Outbound\SamlAssertion(
    $assertionXml,
    Outbound\SamlVersion::Saml20,
);
```

- `string $assertionXml`: the full `saml:Assertion` element as a well-formed XML string. Required, non-empty.
- `SamlVersion $version`: `SamlVersion::Saml11` or `SamlVersion::Saml20`. Required; the version determines the
  expected namespace and the id attribute (`AssertionID` for 1.1, `ID` for 2.0). The assertion root alone has no
  reliable version discriminant, so you state it.

The block keeps no per-message state, so one instance is safe to reuse across messages and under a worker that
holds the middleware for the life of the process.

### Signing with the key the assertion vouches for (Holder-of-Key)

Put the assertion in the header, then sign with `KeyRef::SamlAssertion`. The signature's `ds:KeyInfo` then names
the assertion instead of a certificate, so the receiver resolves the verifying key through it:

```php
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\KeyRef;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;

new WsseMiddleware($profile, outbound: [
    new Outbound\Timestamp(),
    new Outbound\SamlAssertion($assertionXml, Outbound\SamlVersion::Saml20),
    (new Outbound\Signature(new Outbound\CertificateSigningKey($clientCertificate, KeyRef::SamlAssertion)))
        ->withParts([Part::body(), Part::timestamp()]),
]);
```

Order matters: the `SamlAssertion` block has to run first, because the signature finds the assertion in the
header rather than being handed its id. Its version and id are read from the assertion element itself, so the
reference can never describe a different version than the assertion it points at. The header must carry exactly
one assertion; two would leave no single answer to which key the signature claims, and that is refused.

**Name the parts explicitly.** The default `Part::securityHeaderContents()` expands to every element in the
Security header, which here includes the assertion. Signing it stamps a `wsu:Id` on it, and that attribute is
inside what the issuer's own signature covers, so stamping it invalidates the assertion the reference depends
on. Sign the Body and the Timestamp instead, as above.

This is outbound only. Verifying a Holder-of-Key message that a peer sent you needs inbound SAML consumption,
which this major does not implement.

The version is required on the block because the SAML Token Profile references the two versions differently. A
SAML 2.0 assertion is named by the 1.1-profile `#SAMLID` value type and the reference must carry a
`wsse11:TokenType` of `#SAMLV2.0`, while a 1.1 assertion keeps the 1.0-profile `#SAMLAssertionID`. A
version-blind reference can only describe a 1.1 assertion. You state it rather than have it inferred so that an
assertion whose namespace disagrees with what you expected is refused instead of silently re-labelled.

