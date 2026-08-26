# Upgrade guide

## Upgrading to the new major version

Everything below is written against the last released version. This release swaps the old `robrichards/wse-php`
wrapper for an XML-Security layer that lives in this package. You still build security as a list of blocks, so
the idea is familiar, but the names, the credential objects and several defaults changed.

### The XML-Security layer is now part of this package

Signing, encryption, decryption and verification run inside this package on the modern PHP DOM. The cryptography
underneath is split across three engines, which is worth knowing if you scope a CVE watch or an approved-crypto
argument by dependency:

| Operation | Performed by |
|---|---|
| Symmetric ciphers (AES-GCM, AES-CBC, 3DES) | `phpseclib/phpseclib` |
| RSA, DSA and ECDSA signing and verification | `phpseclib/phpseclib` |
| RSA key transport (wrapping and unwrapping the session key) | `phpseclib/phpseclib` |
| Certificate revocation list parsing | `phpseclib/phpseclib` |
| Certificate path validation, key and PEM parsing | `ext-openssl` |
| Digests | `ext-hash` |

So `ext-openssl` is required for the certificate work rather than for the cryptographic operations themselves,
and phpseclib's correctness and timing properties are on the path of every inbound signature verification and
every RSA unwrap an unauthenticated peer can drive. You no longer need `robrichards/wse-php` or `xmlseclibs` at runtime, and the old
encryption-bug patch (the `cweagans/composer-patches` workaround for `wse-php`) is no longer needed. You can
drop that patch and the dev dependency from your project.

`ext-intl` is now a required extension. The inbound timestamp validator parses instants with the ICU date
formatter, so make sure `ext-intl` is installed wherever this package runs.

### PHP 8.4.21 is the minimum

The signing and verification paths canonicalize XML (C14N) through libxml. A libxml defect below the fix that
shipped in **PHP 8.4.21** corrupts the attribute list during canonicalization, which silently breaks signature
digests. The package now requires `~8.4.21 || ~8.5.0`; upgrade your PHP patch level if you are on an earlier
8.4.

### Install ext-gmp or ext-bcmath for RSA performance

phpseclib does the RSA and ECDSA big-integer math in PHP, so its speed depends on the arithmetic backend it
finds. Install `ext-gmp` for native-speed key transport and signatures, or `ext-bcmath`, which on PHP 8.4 is
already fast enough for a typical client. With neither extension the math falls back to a pure-PHP path that
is noticeably slower per message; everything still works, just slower. `ext-bcmath` is commonly enabled by
default, so most installations need no action.

This is not only about throughput. That same math runs the RSA unwrap on the inbound path, which an
unauthenticated peer can drive by sending an encrypted response, so the backend is on a path that is reachable
rather than merely internal.

### Secure defaults changed on the wire

Read this section even if you change nothing else: several defaults moved, so the bytes your peer receives are
not what the previous version sent. If a peer pins the old algorithms, set them back explicitly.

| Setting | Before | Now |
|---|---|---|
| Signature method | `SignatureMethod::RSA_SHA1` | `SignatureMethod::RSA_SHA256` |
| Reference digest | `DigestMethod::SHA1` | `DigestMethod::SHA256` |
| Canonicalization | the `SignatureCanonicalization` enum existed but was never wired to anything | `SignatureCanonicalization::EXC_C14N`, and honoured |
| Data encryption | `DataEncryptionMethod::AES256_CBC` | `DataEncryptionMethod::AES256_GCM` |
| Key transport | `KeyEncryptionMethod::RSA_OAEP_MGF1P` | `KeyEncryptionMethod::RSA_OAEP` |
| Timestamp TTL | 3600 seconds | 300 seconds |
| Encrypted parts | Body **and the signature** (`encryptSignature` defaulted to `true`) | Body only |
| Encryption key reference | had to be passed explicitly | `EncKeyRef::SubjectKeyIdentifier` |
| Signature key reference | had to be passed explicitly | `KeyRef::BinarySecurityToken` |

SHA-1 signing and digests are still selectable, so a peer that has not moved on keeps working:

```php
$profile = new SecurityProfile(crypto: new CryptoPolicy(
    signatureMethod: SignatureMethod::RSA_SHA1,
    digestMethod: DigestMethod::SHA1,
));
```

Inbound, the accepted algorithms are allow-lists rather than "anything the enum can name". The defaults accept
what a modern peer sends; widen them on the `CryptoPolicy` if you must verify a legacy response.

### Two block lists instead of one

The constructor arguments were renamed to say what they do, and named arguments are now supported (the old
constructor was `@no-named-arguments`):

- `outgoing:` is now `outbound:`, the blocks that secure the request you send.
- `incoming:` is now `inbound:`, the blocks that check the response you get back.

`WsseMiddleware` also takes a `SecurityProfile` as its first required argument:

```php
// before
new WsseMiddleware($outgoingEntries, $incomingEntries);

// after
new WsseMiddleware(
    new SecurityProfile(),
    outbound: [ /* ... */ ],
    inbound: [ /* ... */ ],
);
```

The profile reaches every block through the per-message context, so the signing, encryption and verification
blocks take no settings object of their own.

### Header targeting moved from the middleware to the profile

`WsseMiddleware::withActor()` and `WsseMiddleware::withMustUnderstand()` are gone. Both are properties of the
`SecurityProfile` now, because the same value has to drive both directions:

```php
// before
(new WsseMiddleware($outgoing))->withActor('urn:my-gateway')->withMustUnderstand(false);

// after
new WsseMiddleware(
    new SecurityProfile(actorOrRole: 'urn:my-gateway', mustUnderstand: false),
    outbound: $outbound,
);
```

The defaults (`null` and `true`) are the previous behaviour exactly. An untargeted header carrying
`mustUnderstand="1"`. One value drives both directions: outbound it targets the header the blocks write,
inbound it selects the header they read. Set it if your deployment is addressed as a named intermediary rather
than the ultimate receiver: a response whose Security header is addressed to an explicit actor/role is only
processed when the profile names that actor.

### Outbound blocks moved and were renamed

The old `WSSecurity\Entry\*` classes are now `WSSecurity\Outbound\*`:

- `Entry\Timestamp` is now `Outbound\Timestamp`
- `Entry\Username` is now `Outbound\Username`
- `Entry\BinarySecurityToken` is now `Outbound\BinarySecurityToken`
- `Entry\Signature` is now `Outbound\Signature`
- `Entry\Encryption` is now `Outbound\Encryption`
- `Entry\SamlAssertion` is now `Outbound\SamlAssertion`

The `WsseEntry` interface they implemented is now `WSSecurity\Outbound\OutboundAction`, and a block receives a
`WsseContext` instead of a `DOMDocument` and a `WSSESoap`. If you wrote your own entry, that is the signature to
port:

```php
// before
public function __invoke(DOMDocument $envelope, WSSESoap $wsse): void;

// after
public function __invoke(WsseContext $context): void;
```

### The UsernameToken no longer sends a Nonce and Created unless you ask

The old block delegated to `WSSESoap::addUserToken()`, which always appended a `wsse:Nonce` and a `wsu:Created`,
whatever the password mode. `Outbound\Username` now emits them only where they carry meaning: digest mode, where
the digest is computed over both, always does; a `PasswordText` or password-less token sends neither by default.

Peers that require the replay markers on a cleartext token are the reason the withers exist:

```php
// before: nonce and created were always on the wire
new Entry\Username('your-user', 'your-password');

// after: ask for them
(new Outbound\Username('your-user', 'your-password'))
    ->withNonce(true)
    ->withCreated(true);
```

Nothing needs porting for digest tokens.

### Inbound is now a real, explicit list

Before, the response side only knew how to decrypt. It is now its own list of blocks that mirrors the
outbound side:

- `Inbound\Decrypt` decrypts the response. It replaces the old `Entry\Decryption`.
- `Inbound\VerifySignature` verifies the signature and confirms the parts you require were signed by a trusted
  certificate. Checking a response this way is new: the previous version could not verify a response at all.
- `Inbound\ValidateTimestamp` checks the response is fresh within a clock-skew window. This is also new.

A response that fails an inbound check throws a single, uniform security error. It does not reveal which step
failed, which denies a peer the step-identifying detail a forgery or validation oracle needs.

One exposure it does not close, and must not be read as closing: if you opt into an AES-CBC data-encryption
method, the CBC padding oracle stays open. A uniform fault hides which step failed, but an oracle only needs to
know whether the message was accepted at all, and a caller who can trigger requests observes that from the
difference between a returned response and a thrown one. CBC is refused by default for this reason. Narrow the
accepted data-encryption methods to the GCM ciphers, or accept the exposure knowingly. See
[the security profile reference](docs/security-profile.md) for the opt-in and what it costs.

### Locator and preset classes were removed with no replacement

These were public but internal in intent, and the engine that replaced them addresses XML differently. If you
used one directly, there is no like-for-like substitute:

| Removed | What to do instead |
|---|---|
| `WSSecurity\Xml\Locator\SecurityLocator` | `WSSecurity\Xml\Builder\SecurityHeader::locate()` returns the header addressed to this receiver |
| `WSSecurity\Xml\Locator\SignatureLocator` | Internal to verification now; `Inbound\VerifySignature` is the supported entry point |
| `WSSecurity\Xml\Locator\BinaryTokenLocator` | `WSSecurity\Xml\Locator\BinaryToken` locates a token by its content within a given header |
| `WSSecurity\Xml\Locator\EncryptedKeyLocator` | Internal to decryption now; `Inbound\Decrypt` is the supported entry point |
| `WSSecurity\Xml\Legacy\LegacyInterop` | The `wse-php` bridge it existed for is gone |
| `WSSecurity\Xml\Xpath\WssePreset` | Each query now declares the prefixes it uses, so no shared preset exists |

### Credentials are value objects under `KeyStore`

The credential classes moved out of `WSSecurity\KeyStore\` to `Soap\Psr18WsseMiddleware\KeyStore\`. Update your
`use` statements; constructing them from PEM contents is unchanged, and `Key::fromFile()` /
`ClientCertificate::fromFile()` / `Certificate::fromFile()` still read a file for you.

- `KeyStore\Certificate`: a public X.509 certificate. `withPassphrase()` is gone from it; a public certificate
  never needed one. `Certificate::fromBase64Der()` is new, for a certificate that arrives as base64 DER.
- `KeyStore\Key`: a private key. Unchanged apart from the namespace.
- `KeyStore\ClientCertificate`: a combined certificate-and-key bundle to sign with.
- `KeyStore\TrustStore`: new: the anchors inbound verification trusts (`TrustStore::fromCertificates(...)`).
- `isCertificate()` is gone from all three. Each class now says what it is by its type, so nothing has to ask.
- `KeyInterface` is gone with it. The blocks name the concrete credential they need, so a block that signs asks
  for a `ClientCertificate` and a block that encrypts for a recipient `Certificate`. If you accepted
  `KeyInterface` in your own code, pick the concrete class the call site actually needs.

Loading from a `.p12` / `.pfx` is new and goes through `KeyStore\Pkcs12Bundle`: decode the blob once, then
derive each credential from the bundle so it is parsed a single time.

```php
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\KeyStore\Pkcs12Bundle;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;

$bundle = Pkcs12Bundle::fromFile('client.p12', 'secret');   // or Pkcs12Bundle::fromString($bytes, 'secret')

$clientCertificate = ClientCertificate::fromPkcs12($bundle);
$recipient = Certificate::fromPkcs12(Pkcs12Bundle::fromFile('service.p12', 'secret'));
$trustStore = TrustStore::fromPkcs12(Pkcs12Bundle::fromFile('service.p12', 'secret'));
```

A PEM file loads through `KeyStore\Pem`, which now reads a file as well as writing one. A trusted-CA file
(several certificates concatenated, no private key) is the usual case:

```php
use Soap\Psr18WsseMiddleware\KeyStore\Pem;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;

$trustStore = TrustStore::fromPem(Pem::fromFile('anchors.pem'));   // or Pem::fromString($bytes)
```

- `Pem::fromString()`, `Pem::fromFile()`, `Pem::certificates()`, `Pem::privateKey()` and
  `Pem::certificatesIn()` are new.
- `TrustStore::fromPem()` is new, and makes **every** certificate in the bundle an anchor. This is the path for a
  trusted-CA file or a converted Java truststore; `TrustStore::fromPkcs12()` is for an identity bundle and skips
  entry 0 as the leaf certificate, so do not use it for a truststore or you lose one anchor.
- `Pem` reads a file that also carries a private key, and hands it back through `Pem::privateKey()`. Refusing
  key material is `TrustStore::fromPem()`'s job, because a trust store is what a key has no business in; the
  message it throws names `ClientCertificate` and `Key` as the two classes that do take one.
- `ClientCertificate::publicCertificate()` now returns the end-entity certificate wherever the file lists it,
  derived from issuer linkage rather than from position. If your combined file put its CA certificate ahead of
  your own, the previous version advertised the CA in the binary security token while signing with your key,
  and the peer rejected the signature. Nothing to change on your side; such a file now works.
- Text outside the certificate armor is ignored, so output from `openssl pkcs12 -nokeys` loads as it comes.

### Blocks take credentials, not crypto wiring

`Entry\Signature` and `Entry\Encryption` each took a key plus a `KeyIdentifier` object. The blocks now take the
credential and an enum case, and build the engine service they need internally with secure defaults:

```php
// before
new Entry\Signature($privateKey, new BinarySecurityTokenIdentifier());
new Entry\Encryption($recipientKey, new X509SubjectKeyIdentifier($certificate));
new Entry\Decryption($privateKey);

// after
new Outbound\Signature($clientCertificate);                  // KeyRef::BinarySecurityToken by default
new Outbound\Encryption($recipientCertificate);              // EncKeyRef::SubjectKeyIdentifier by default
new Inbound\Decrypt($privateKey);
new Inbound\VerifySignature($trustStore, signed: [Part::body(), Part::timestamp()]);
```

For the rare case where you need a custom engine service, override it with a `with*()` method
(`Outbound\Signature::withSigner`, `Outbound\Encryption::withEncryptor`, `Inbound\Decrypt::withDecryptor`,
`Inbound\VerifySignature::withVerifier`) rather than a constructor argument. See
[Custom engine services](docs/xmlsecurity.md#custom-engine-services) for the SPI those methods take.

### What the Signature block signs is now a list of parts

The boolean switches are gone. `withSignAllHeaders()`, `withSignBody()`, `withSignSpecificHeaders()` and
`withInsertBefore()` no longer exist; you name the regions to sign as a list of `Part` values instead:

```php
// before
(new Entry\Signature($key, $keyIdentifier))
    ->withSignAllHeaders(true)
    ->withSignBody(true);

// after
(new Outbound\Signature($clientCertificate))
    ->withParts([Part::body(), Part::soapHeaders()]);
```

The default is `[Part::body(), Part::securityHeaderContents()]`, where `securityHeaderContents()` is a dynamic
part covering every element present in the `wsse:Security` header when the request is built. The Timestamp and
any tokens. The previous default signed the Body and all SOAP headers, so the closest equivalent is
`[Part::body(), Part::soapHeaders(), Part::securityHeaderContents()]`.

The available factories are `body()`, `timestamp()`, `usernameToken()`, `binarySecurityToken()`,
`securityHeaderContents()`, `soapHeaders()` (every SOAP header block except `wsse:Security`. The equivalent of
`wse-php`'s `signAllHeaders`), `element(namespace, localName)` and `byId(id)`. The two dynamic parts also work
inbound: pass them to `Inbound\VerifySignature`'s `signed:` list to require every Security-header token (or
every other SOAP header) was signed.

`Outbound\Encryption` takes the same `withParts()` list to choose what gets encrypted, and defaults to the Body
alone. Its `withEncryptSignature(bool)` switch is gone with the other booleans: and it used to default to
`true`, so the previous version encrypted the signature as well. Name the signature as a part to keep that:

```php
(new Outbound\Encryption($recipientCertificate))
    ->withParts([Part::body(), Part::element('http://www.w3.org/2000/09/xmldsig#', 'Signature')]);
```

### Key references are now enums

The `WSSecurity\KeyIdentifier\*` classes are gone. You pick a reference style with an enum case instead of
constructing an object, and the certificate it describes is derived from the credential the block already has:

| Before | After |
|---|---|
| `new BinarySecurityTokenIdentifier()` | `KeyRef::BinarySecurityToken` |
| `new X509SubjectKeyIdentifier($certificate)` | `KeyRef::SubjectKeyIdentifier` |
|. | `KeyRef::IssuerSerial` (new) |
|. | `KeyRef::Thumbprint` (new) |

`KeyRef` selects the reference for `Outbound\Signature`; `EncKeyRef` offers the same four cases for
`Outbound\Encryption` (encryption has no Holder-of-Key equivalent). Both live under
`WSSecurity\Outbound\KeyReference\`:

```php
new Outbound\Signature($clientCertificate, KeyRef::SubjectKeyIdentifier);
new Outbound\Encryption($recipientCertificate, EncKeyRef::IssuerSerial);
```

`SamlKeyIdentifier` is now `SamlAssertionKeyIdentifier` and requires a `SamlVersion` as its second argument.
For the ordinary Holder-of-Key flow you no longer construct it yourself: pass `KeyRef::SamlAssertion` and the
block reads the assertion out of the header. Build it by hand only if you are driving the engine directly, and
hand it over with `Outbound\Signature::withKeyIdentifier()`:

```php
// before
new SamlKeyIdentifier($assertionId);

// after
new SamlAssertionKeyIdentifier($assertionId, SamlVersion::Saml20);
```

The SAML Token Profile references the two versions differently, and the old class always emitted the SAML 1.1
shape. A reference to a SAML 2.0 assertion needs the 1.1-profile `#SAMLID` value type plus a `wsse11:TokenType`
of `#SAMLV2.0`, which the old form could not express. So if you were referencing a 2.0 assertion, the reference
your peer received described a 1.1 one. Pass `SamlVersion::Saml11` to keep exactly the previous wire format.

`KeyRef` also gained a fifth case, `SamlAssertion`, for the Holder-of-Key flow: the signature points at the
`saml:Assertion` an `Outbound\SamlAssertion` block placed in the header earlier in the list. See
[the outbound block reference](docs/outbound-blocks.md) for the composition and the part list it needs.

`CustomKeyIdentifier` still exists for a value type this package does not model, under
`WSSecurity\Outbound\KeyReference\` with the rest. Reach it with
`Outbound\Signature::withKeyIdentifier($keyIdentifier)`, which overrides the `keyRef` passed at construction.
`ReferencingKeyIdentifier` was removed: every reference the package emits is now either one of the five `KeyRef`
cases or a key identifier you supplied yourself.

### `SamlAssertion::assertionId()` was removed

The block no longer keeps the id of the last assertion it imported, because holding per-message state on a block
that a long-running worker reuses is a cross-request hazard. Nothing needs it any more: a Holder-of-Key
signature reads the assertion straight out of the header via `KeyRef::SamlAssertion`. If you called
`assertionId()` for logging, read the `ID` (2.0) or `AssertionID` (1.1) attribute off your own assertion XML,
which you already hold.

### The SAML assertion block takes XML as a string

`Entry\SamlAssertion` took a `DOMDocument` you had parsed yourself. `Outbound\SamlAssertion` takes the raw XML
plus its version, so the package controls the parse: it rejects a DOCTYPE before reading anything, which a
document you hand in has already been exposed to:

```php
// before
new Entry\SamlAssertion($domDocument);

// after
new Outbound\SamlAssertion($assertionXml, SamlVersion::Saml20);
```

### Algorithm enums moved, and the settings live on `CryptoPolicy`

`SignatureMethod`, `DigestMethod`, `SignatureCanonicalization`, `DataEncryptionMethod` and
`KeyEncryptionMethod` moved from `Soap\Psr18WsseMiddleware\WSSecurity\` to
`Soap\Psr18WsseMiddleware\Algorithm\`. They are W3C XML-Security algorithm identifiers, independent of the SOAP
layer. Update your `use` statements. Two cases went away: `SignatureMethod::HMAC_SHA1` (a symmetric MAC, which
this package does not implement), and `SignatureMethod::RSA_OAEP` (a key-transport URI that was never a signature
method). `KeyTransportAlgorithm` and `OaepHash` are new.

Where you set them changed too. `Entry\Signature::withSignatureMethod()` / `withDigestMethod()` and
`Entry\Encryption::withDataEncryptionMethod()` / `withKeyEncryptionMethod()` still exist on the blocks for a
one-off override, but the defaults for every block come from a `CryptoPolicy` on the profile:

```php
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;

$profile = new SecurityProfile(crypto: new CryptoPolicy(
    signatureMethod: SignatureMethod::RSA_SHA512,
    dataEncryptionMethod: DataEncryptionMethod::AES256_CBC,
));
```

`SecurityProfile` itself carries only the WS-Security timestamp window (`timestampTtl`, `clockSkew`), and the
header targeting; read the algorithm settings back through `$profile->crypto()`. The split lets the
XML-Security layer be driven by a `CryptoPolicy` alone, without the SOAP profile.

`CryptoPolicy` is also where the inbound allow-lists live: `acceptedSignatureMethods`, `acceptedDigestMethods`,
`acceptedKeyEncryptionMethods`, `acceptedDataEncryptionMethods`, `acceptedOaepHashes` and
`acceptedCanonicalizations`. Leave them unset to keep the secure defaults.

### New algorithms you can opt into

- **ECDSA signing.** `SignatureMethod` gained `ECDSA_SHA256`, `ECDSA_SHA384` and `ECDSA_SHA512`. Select one with
  `Outbound\Signature::withSignatureMethod(SignatureMethod::ECDSA_SHA256)`; it needs an EC certificate and key.
  Inbound, the ECDSA methods are in the default accepted signature allow-list.
- **RSA-OAEP-SHA256 key transport.** The default is RSA-OAEP with a SHA-1 label hash, which is what interop
  peers expect. To move a block to SHA-256, pass
  `Outbound\Encryption::withKeyTransportAlgorithm(KeyTransportAlgorithm::oaepSha256())`. The named constructors
  are `oaepSha1()`, `oaepSha256()`, `legacyMgf1p()` and `rsa1_5()`. There is no `withOaepHash()` setter on the
  block; to move every block at once, set `oaepHash` on the profile's `CryptoPolicy` instead. Inbound, both
  SHA-1 and SHA-256 are accepted by default, and an `xenc11:MGF` child the peer omits is read as the spec
  default MGF1-SHA1 rather than as a declared SHA-1 that has to match the label.
- **AES-GCM data encryption.** `AES128_GCM`, `AES192_GCM` and `AES256_GCM` were already available; GCM is now
  the default. The CBC variants remain selectable for a peer that requires them.
- **Pinned namespace prefixes.** `Outbound\Signature::withInclusivePrefixes()` makes an exclusive
  canonicalization emit an `ec:InclusiveNamespaces PrefixList`, pinning the ancestor namespace declarations it
  would otherwise drop. It takes no argument: the list is computed per signed element from the declarations
  that element actually needs. Off by default; turn it on for a peer that needs an ancestor declaration
  preserved. Inbound, a PrefixList sent by a peer is read and honoured either way.
- **Inclusive canonicalization inbound.** `SignatureCanonicalization`'s inclusive variants `C14N` and
  `C14N_COMMENTS` are unchanged, but only the exclusive variants are accepted inbound by default. If you verify
  responses canonicalized inclusively, add the variant to the profile's `acceptedCanonicalizations`. Canonical
  XML 1.1 is not supported.

### One WS-Addressing middleware

`WsaMiddleware2005` is gone. There is now a single `WsaMiddleware` covering both addressing versions, and its
default is the W3C 2005/08 one: the namespace `WsaMiddleware2005` used to provide. **If you used the plain
`WsaMiddleware`, you were on the 2004/08 submission namespace and must now select it explicitly.**

Its single string argument became a `WsaOptions` object, so one object owns the addressing version and every
message-addressing property:

```php
// before
new WsaMiddleware();                                                // 2004/08, anonymous ReplyTo
new WsaMiddleware('https://your-app.example/reply');                // 2004/08, explicit ReplyTo
new WsaMiddleware2005();                                            // 2005/08, anonymous ReplyTo

// after
new WsaMiddleware(new WsaOptions(WsaNamespace::Submission200408));
new WsaMiddleware(new WsaOptions(WsaNamespace::Submission200408, replyTo: 'https://your-app.example/reply'));
new WsaMiddleware();                                                // 2005/08 is the default now
```

The `WSA_ADDRESS_ANONYMOUS` constant is gone; each version's anonymous URI comes from
`WsaNamespace::anonymousUri()` and is used automatically when `replyTo` is left unset.

`WsaOptions` also exposes what the middleware previously derived with no way to override: `action` and `to`:
plus two properties that could not be sent at all before: `from` and `faultTo`. All of them default to `null`,
which keeps the previous behaviour: `action` from the request's `SOAPAction`, `to` from the request URI, and
`From`/`FaultTo` omitted. `wsa:MessageID` is still generated per message and is deliberately not configurable.

### Send or receive secured SOAP attachments

New capability, so there is nothing to migrate. Do this only if your service protects attachments.

Require `php-soap/psr18-attachments-middleware` 0.12.0 or newer, which is the release where an attachment
describes itself in the MIME headers it travels with:

```bash
composer require "php-soap/psr18-attachments-middleware:^0.12"
```

List `WsseMiddleware` before `AttachmentsMiddleware`. The first plugin in a `PluginClient` is the outermost,
and WSSE has to see plain XML on the way out and a split multipart on the way back:

```php
new WsseMiddleware(
    new SecurityProfile(),
    outbound: [
        (new Outbound\Signature($clientCertificate))
            ->withAttachments(AttachmentParts::request($attachments, ExternalPartCoverage::Complete)),
    ],
    inbound: [
        (new Inbound\VerifySignature($trustStore))
            ->withAttachments(AttachmentParts::response($attachments, ExternalPartCoverage::Complete)),
    ],
),
new AttachmentsMiddleware($attachments, AttachmentType::Swa),
```

Register the parts on every block that should cover them. `Outbound\Signature`, `Inbound\VerifySignature`,
`Outbound\Encryption` and `Inbound\Decrypt` each take `withAttachments()`, and a block without it protects the
document alone. Registering parts on an inbound block is the *requirement* that they be protected, so a peer
that omits one is refused rather than silently accepted.

Choose how much of each part a protection covers, which is decidable from the peer's WSDL:

| The peer's WSDL says | Configure |
|---|---|
| `<sp:SignedParts><sp:Attachments/></sp:SignedParts>` | `ExternalPartCoverage::Complete` |
| `<sp:Attachments><sp13:ContentSignatureTransform/></sp:Attachments>` | `ExternalPartCoverage::Content` |
| `<sp:EncryptedParts><sp:Attachments/></sp:EncryptedParts>` | Either satisfies the policy. `Content` outbound; be ready to accept `Complete` inbound |
| Nothing about attachments | Neither. Do not register attachment parts on the blocks |

A bare `<sp:Attachments/>` means `Complete`: content-only is the opt-in. There is no default, so name the
coverage where the adapter is built:

```php
AttachmentParts::request($attachments, ExternalPartCoverage::Complete)
```

If you implemented the `ExternalParts` seam yourself rather than using `AttachmentParts`, add
`collectSealed()` to it. Return `collect()` unless you compose a canonical header block, in which case return
the part's own octets: a cipher addresses the MIME part, while a signature covers the composition.

Read [docs/attachments.md](docs/attachments.md) before turning it on. It carries the wire format, the ordering
rules, and the list of what is refused, including the media types this release will not sign.
