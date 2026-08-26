# Outbound blocks

[← Back to the deep dives](../README.md#deep-dives)

The blocks that secure the request you send. Every block is a small, immutable value object you drop
into the `outbound` list: a short example, then every constructor argument and fluent method with its
default and what it expects.

See [Inbound blocks](inbound-blocks.md) for their response-side counterparts, and the
[README](../README.md#the-building-blocks) for the order to list them in.

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
  configured on the `Signature` block via
  [`withCertificatePath()`](#outbound-signature); reach for this constructor only when the token has to stand on
  its own.

## Outbound: `Signature`

Adds a detached, multi-reference `ds:Signature` to the Security header. You choose the signing key (and the
advertised certificate), how that certificate is referenced in `ds:KeyInfo`, which parts are signed, and the
algorithms.

```php
use Soap\Psr18WsseMiddleware\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;

$clientCertificate = ClientCertificate::fromFile('client.pem')->withPassphrase('xxx');

// Default: sign the Body and everything in the Security header, reference the key via an embedded
// BinarySecurityToken.
new Outbound\Signature($clientCertificate, keyRef: Outbound\KeyReference\KeyRef::BinarySecurityToken);

// Sign only the body, reference by Subject Key Identifier:
(new Outbound\Signature($clientCertificate, keyRef: Outbound\KeyReference\KeyRef::SubjectKeyIdentifier))
    ->withParts([Part::body()]);
```

- `ClientCertificate $clientCertificate`: the certificate-and-key bundle to sign with. The private key signs;
  the public certificate is advertised in `ds:KeyInfo`. Required.
- `keyRef: KeyRef $keyRef = KeyRef::BinarySecurityToken`: how the certificate is referenced. Pass it as a named
  argument (`keyRef:`). Default `KeyRef::BinarySecurityToken`, the X.509 direct-reference interop default: a
  `wsse:BinarySecurityToken` is embedded and the signature points at it by `wsu:Id`. The other cases
  (`SubjectKeyIdentifier`, `IssuerSerial`, `Thumbprint`) put an inline reference derived from the certificate and
  embed no token. See [Choosing parts and key references](parts-and-key-references.md).
- `withAttachments(ExternalParts $attachments): self`: also cover the message's attachments, in the same
  `ds:Signature` as the in-document parts. Off by default. Pass
  `AttachmentParts::request($attachmentStorage, ExternalPartCoverage::Complete)`; see [Attachment security](attachments.md).
  ```php
  use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\AttachmentParts;

  (new Outbound\Signature($clientCertificate))
      ->withAttachments(AttachmentParts::request($attachmentStorage, ExternalPartCoverage::Complete));
  ```
  The second argument says how much of each part the signature covers: `ExternalPartCoverage::Content` by
  default, `Complete` to cover the canonical MIME header block as well. A bare `<sp:Attachments/>` in the
  peer's policy means `Complete`, so read the WSDL rather than the default; the
  [configuration table](attachments.md#how-much-of-a-part-a-protection-covers) is the whole rule.
  Adds coverage rather than replacing it: an attachment reference sits alongside whatever `withParts()` asks
  for. A `text/*` attachment is digested over its normalized line endings, which is what the transform
  defines. An XML attachment is refused, because the profile canonicalizes it with exclusive C14N before
  digesting and that is not implemented; see [Attachment security](attachments.md).
- `withCertificatePath(CertificateChain $path): self`: send your whole certificate chain in the token (a
  `#X509PKIPathv1` `wsse:BinarySecurityToken`) instead of the leaf certificate alone. Off by default. Turn it on
  for a server that will not complete the chain from its own store and needs the intermediates handed to it:
  ```php
  use Soap\Psr18WsseMiddleware\KeyStore\Pkcs12Bundle;

  $bundle = Pkcs12Bundle::fromFile('client.p12', 'xxx');

  (new Outbound\Signature(ClientCertificate::fromPkcs12($bundle)))
      ->withCertificatePath($bundle->chain);
  ```
  A `.p12` already contains the chain, which is where it usually comes from; a PEM signing identity has none to
  offer. The chain must start with the certificate you sign with, and `keyRef` must be
  `KeyRef::BinarySecurityToken`, or the call throws.
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

  (new Outbound\Signature($clientCertificate, keyRef: Outbound\KeyReference\KeyRef::BinarySecurityToken))
      ->withSignatureMethod(SignatureMethod::ECDSA_SHA256);
  ```
  The ECDSA cases are `ECDSA_SHA256`, `ECDSA_SHA384` and `ECDSA_SHA512` (the xmldsig-more URIs). They require an
  EC certificate and key; an RSA key paired with an ECDSA method will not sign. The RSA cases stay `RSA_SHA256`
  (the default), `RSA_SHA384` and `RSA_SHA512`.

  Two legacy cases exist and are **not** accepted inbound by default: `RSA_SHA1` and `DSA_SHA1` (which needs a
  DSA key to sign with). Use either only for a peer that requires it, and add it to `acceptedSignatureMethods`
  to verify one (see [Security profile and defaults](security-profile.md)).
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

  (new Outbound\Signature($clientCertificate, keyRef: Outbound\KeyReference\KeyRef::BinarySecurityToken))
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
  (new Outbound\Signature($clientCertificate))
      ->withInclusivePrefixes();
  ```
  Nothing else changes: the list is worked out per element for you, and the receiver reads it from the signature.
  It has no effect on an inclusive canonicalization.

## Outbound: `Encryption`

Encrypts the requested parts of the message via XML-Enc. It wraps a fresh session key for the recipient's
certificate and encrypts the parts with it. Place it **after** `Signature` (sign-then-encrypt).

```php
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

$recipient = Certificate::fromFile('service.pub');

// Default: encrypt the Body, reference the recipient key by Subject Key Identifier.
new Outbound\Encryption($recipient);

// Encrypt the body, reference by IssuerSerial:
new Outbound\Encryption($recipient, encKeyRef: Outbound\KeyReference\EncKeyRef::IssuerSerial);
```

- `Certificate $recipientCertificate`: the recipient's public certificate, used to wrap the session key.
  Required.
- `encKeyRef: EncKeyRef $encKeyRef = EncKeyRef::SubjectKeyIdentifier`: how the recipient's certificate is
  referenced inside the `xenc:EncryptedKey`, so it knows which private key unwraps the session key. Default
  `EncKeyRef::SubjectKeyIdentifier`. The other cases are `IssuerSerial`, `Thumbprint` and `BinarySecurityToken`.
- `withParts(list<Part> $parts): self`: which parts to encrypt. Default is `[Part::body()]`. An empty list
  throws unless attachments are registered: it is not read as "the default". Encrypting nothing still wraps a
  session key and appends an `xenc:EncryptedKey`, so the Body would leave in cleartext under a message that
  reads as encrypted in every log and packet capture of it. With `withAttachments()` already applied an empty
  list is allowed, because encrypting only the attachments is a real configuration; register them first, since
  the check runs when `withParts()` is called.
- `withAttachments(ExternalParts $attachments): self`: also encrypt the message's attachments, under the same
  session key and in the same `xenc:EncryptedKey`. Off by default. Pass
  `AttachmentParts::request($attachmentStorage, ExternalPartCoverage::Content)`; see [Attachment security](attachments.md).
  ```php
  use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\AttachmentParts;

  (new Outbound\Encryption($recipient))
      ->withAttachments(AttachmentParts::request($attachmentStorage, ExternalPartCoverage::Content));
  ```
  This block emits content-only ciphertext, so an adapter built with `ExternalPartCoverage::Complete` is
  refused. No policy can require the wider one: a peer validates the coverage of a signature and never of an
  encryption.
  Each sealed part's `Content-Type` becomes `application/octet-stream` and its original media type is recorded
  on the `xenc:EncryptedData`, so the far side can restore it. An element whose content is or contains an
  `xop:Include` cannot be encrypted at all: that would protect the pointer while the bytes travel in the clear.
  Encrypt the attachment instead.
- `withDataEncryptionMethod(DataEncryptionMethod $method): self`: the bulk-data cipher. Default: the profile's
  `dataEncryptionMethod()` (AES-256-GCM).
- `withKeyEncryptionMethod(KeyEncryptionMethod $method): self`: the key-transport method that wraps the
  session key. Default: the profile's `keyEncryptionMethod()` (RSA-OAEP). This sets only the method; the OAEP
  hash is resolved from the profile (or its default, SHA-1). To pin the method and the hash together, use
  `withKeyTransportAlgorithm` instead.
- `withKeyTransportAlgorithm(KeyTransportAlgorithm $algorithm): self`: the whole key-transport choice (method
  plus OAEP hash) in one atomic value, so an invalid method/hash pairing cannot be expressed. This override wins
  over both `withKeyEncryptionMethod` and the profile. The default key transport is RSA-OAEP with SHA-1. The
  label hash is what the previous releases used, but the `Algorithm` URI is not: the default moved from
  `xmlenc#rsa-oaep-mgf1p` to `xenc11#rsa-oaep`. A peer that pins the old URI needs
  `KeyTransportAlgorithm::legacyMgf1p()`. Select RSA-OAEP-SHA256 when the server expects it:
  ```php
  use Soap\Psr18WsseMiddleware\Algorithm\KeyTransportAlgorithm;

  (new Outbound\Encryption($recipient))
      ->withKeyTransportAlgorithm(KeyTransportAlgorithm::oaepSha256());
  ```
  The named constructors are `KeyTransportAlgorithm::oaepSha1()` (the default), `oaepSha256()`, `legacyMgf1p()`
  (RSA-OAEP-MGF1P, SHA-1), and `rsa1_5()` (RSA-1_5, rejected inbound by default).

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
    (new Outbound\Signature($clientCertificate, keyRef: KeyRef::SamlAssertion))
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

