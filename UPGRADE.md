# Upgrade guide

## Upgrading to the new major version

This release swaps the old `robrichards/wse-php` wrapper for a WSSE engine that lives in this package. You
still build security as a list of blocks, so the idea is familiar, but the names and some of the moving
parts changed. Here is what to check when you upgrade.

### The engine is now part of this package

Signing, encryption, decryption and verification run inside this package on the modern PHP DOM, `ext-openssl`
(symmetric ciphers, digests and certificates) and the `phpseclib/phpseclib` library (RSA and ECDSA key
transport and signatures). You no longer need `robrichards/wse-php` or `xmlseclibs` at runtime, and the old
encryption-bug patch (the `cweagans/composer-patches` workaround for `wse-php`) is no longer needed. You can
drop that patch and the dev dependency from your project.

`ext-intl` is now a required extension. The inbound timestamp validator parses instants with the ICU date
formatter, so make sure `ext-intl` is installed wherever this package runs.

### `SamlAssertionKeyIdentifier` takes the SAML version

`SamlAssertionKeyIdentifier` now requires a `SamlVersion` as its second constructor argument:

```php
// before
new SamlAssertionKeyIdentifier($assertionId);

// after
new SamlAssertionKeyIdentifier($assertionId, SamlVersion::Saml20);
```

The SAML Token Profile references the two versions differently, and the old single-argument form always emitted
the SAML 1.1 shape. A reference to a SAML 2.0 assertion needs the 1.1-profile `#SAMLID` value type plus a
`wsse11:TokenType` of `#SAMLV2.0`, which the old form could not express — so if you were referencing a 2.0
assertion, the reference your peer received described a 1.1 one. Pass `SamlVersion::Saml11` to keep exactly the
previous wire format.

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

### Blocks are now one-liners; no engine wiring

The signing, encryption, decryption and verification blocks build the engine service they need internally,
with secure defaults. You construct them directly:

```php
new Outbound\Signature($clientCertificate, keyRef: Outbound\KeyReference\KeyRef::BinarySecurityToken);
new Outbound\Encryption($recipientCertificate);
new Inbound\Decrypt($privateKey);
new Inbound\VerifySignature($trustStore, signed: [Part::body(), Part::timestamp()]);
```

If you previously passed engine services into the blocks yourself, you can delete that wiring. Each of those
blocks builds the bundled implementation by default; for the rare case where you need a custom one, override it
with a `with*()` method (`Outbound\Signature::withSigner`, `Outbound\Encryption::withEncryptor`,
`Inbound\Decrypt::withDecryptor`, `Inbound\VerifySignature::withVerifier`) rather than a constructor argument.

### The Signature block signs the Security-header contents by default

`Outbound\Signature`'s default signed parts changed from `[Part::body(), Part::timestamp()]` to
`[Part::body(), Part::securityHeaderContents()]`. The new `securityHeaderContents()` is a dynamic part that
signs every element present in the `wsse:Security` header when the request is built — the Timestamp and any
tokens — so the common setup (Timestamp + Signature) still signs the Body and the Timestamp, and additionally
covers the tokens. Two consequences:

- The default no longer fails when there is no Timestamp block; it signs whatever the header contains.
- To keep the exact old set, configure it explicitly:
  `->withParts([Part::body(), Part::timestamp()])`.

New `Part` factories accompany the change: `securityHeaderContents()`, `soapHeaders()` (every SOAP header block
except `wsse:Security` — the equivalent of `wse-php`'s `signAllHeaders`), and the `usernameToken()` /
`binarySecurityToken()` shortcuts. The two dynamic parts also work inbound: pass them to
`Inbound\VerifySignature`'s `signed:` list to require every Security-header token (or every other SOAP header)
was signed.

### Keys, certificates and trust anchors live under `KeyStore`

The credentials the blocks take are value objects under the `Soap\Psr18WsseMiddleware\KeyStore` namespace (the
clock seam used by the timestamp blocks sits under `Soap\Psr18WsseMiddleware\Clock`):

- `KeyStore\Certificate` — a public X.509 certificate (`Certificate::fromFile('cert.pub')`).
- `KeyStore\Key` — a private key (`Key::fromFile('key.priv')->withPassphrase('…')` when encrypted).
- `KeyStore\ClientCertificate` — a combined certificate-and-key bundle to sign with.
- `KeyStore\TrustStore` — the anchors inbound verification trusts (`TrustStore::fromCertificates(...)`).

Loading from a `.p12` / `.pfx` goes through `KeyStore\Pkcs12Bundle`: decode the blob once, then derive each
credential from the bundle so it is parsed a single time.

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

### Two block lists instead of one

The constructor arguments were renamed to say what they do:

- `outgoing:` is now `outbound:`, the blocks that secure the request you send.
- `incoming:` is now `inbound:`, the blocks that check the response you get back.

`WsseMiddleware` now takes a `SecurityProfile` as its first required argument:

```php
new WsseMiddleware(
    new SecurityProfile(),
    outbound: [ /* ... */ ],
    inbound: [ /* ... */ ],
);
```

The profile reaches every block through the per-message context, so the signing, encryption and verification
blocks no longer take a profile of their own.

### Outbound blocks moved and were renamed

The old `WSSecurity\Entry\*` classes are now `WSSecurity\Outbound\*`:

- `Entry\Timestamp` is now `Outbound\Timestamp`
- `Entry\Username` is now `Outbound\Username`
- `Entry\BinarySecurityToken` is now `Outbound\BinarySecurityToken`
- `Entry\Signature` is now `Outbound\Signature`
- `Entry\Encryption` is now `Outbound\Encryption`
- `Entry\SamlAssertion` is now `Outbound\SamlAssertion`

### Inbound is now a real, explicit list

Before, the response side only knew how to decrypt. It is now its own list of blocks that mirrors the
outbound side:

- `Inbound\Decrypt` decrypts the response. It replaces the old `Entry\Decryption`.
- `Inbound\VerifySignature` verifies the signature and confirms the parts you require were signed by a trusted certificate. Checking a response this way is new.
- `Inbound\ValidateTimestamp` checks the response is fresh within a clock-skew window. This is also new.

### Key references are now enums

The `WSSecurity\KeyIdentifier\*` classes are gone, and the old factory-style calls
(`KeyRef::binarySecurityToken()`) are gone with them. You now pick a reference style with a small enum case.
For signatures, use `KeyRef::BinarySecurityToken`, `KeyRef::SubjectKeyIdentifier`, `KeyRef::IssuerSerial` or
`KeyRef::Thumbprint`. For encryption, `EncKeyRef` offers the same set. Both live under
`WSSecurity\Outbound\KeyReference\`.

Because `Outbound\Signature` takes the optional engine service before the key reference, pass the reference as
a named argument: `new Outbound\Signature($clientCertificate, keyRef: Outbound\KeyReference\KeyRef::BinarySecurityToken)`.

### Algorithm enums moved

The algorithm enums (`SignatureMethod`, `DigestMethod`, `SignatureCanonicalization`, `DataEncryptionMethod`,
`KeyEncryptionMethod`, `KeyTransportAlgorithm`, `OaepHash`) live at the package root under
`Soap\Psr18WsseMiddleware\Algorithm\` — they are W3C XML-Security algorithm identifiers, independent of the SOAP
layer. Update your `use` statements. The defaults are secure on their own, so in most cases you can stop passing
these explicitly.

### SecurityProfile split: algorithm settings moved to CryptoPolicy

`SecurityProfile` now carries only the WS-Security timestamp window (`timestampTtl`, `clockSkew`) and composes a
`Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy` that holds the algorithm choices and inbound accept
allow-lists. Pass algorithm settings through the `crypto:` argument:

```php
// before
$profile = new SecurityProfile(signatureMethod: SignatureMethod::RSA_SHA512);
// after
$profile = new SecurityProfile(crypto: new CryptoPolicy(signatureMethod: SignatureMethod::RSA_SHA512));
```

Read the settings back through `$profile->crypto()`. `SecurityProfile::default()` is unchanged. The split lets
the XML-Security engine be driven by a `CryptoPolicy` alone, without the SOAP profile.

### The XML-Security engine no longer reaches into the SOAP header (custom engine services only)

This affects you only if you drive the signer/encryptor directly or ship a custom `XmlSigner`/`XmlEncryptor` —
the `Outbound\Signature` and `Outbound\Encryption` blocks are configured exactly as before.

The engine used to locate the `wsse:Security` header itself. It now takes the container element to attach to as
an explicit input, so it carries no SOAP knowledge:

- `SigningRequest` and `EncryptionRequest` gained a required first argument, `Dom\Element $container` — the
  element the `ds:Signature` / `xenc:EncryptedKey` is appended to. The caller locates it (the blocks pass their
  `wsse:Security` header).
- How a signed or encrypted node gets its referenceable id is a `Soap\Psr18WsseMiddleware\XmlSecurity\IdMinter`,
  and how a reference resolves back to its element is its read-side twin, the new
  `Soap\Psr18WsseMiddleware\XmlSecurity\IdLookup`. The engine no longer hard-codes `wsu:Id` anywhere; both sides
  of the id convention are injected. `Signer::create()`, `Encryptor::create()`, `Verifier::create()` and
  `Decryptor::create()` each accept an optional `IdLookup` (the minters/lookups default to the shipped
  `XmlIdMinter`/`XmlIdLookup`, which use the W3C `xml:id`), so a standalone caller works with zero config. The
  blocks inject the `wsu:Id` pair (`WsuIdMinter`/`WsuIdLookup`), as the WS-Security profile mandates — the wire
  output is unchanged. **A minter and lookup passed together must share one id convention.**
- `IdMinter::mint()` is now idempotent: minting a node that already carries an id under the convention returns
  that id rather than stamping a second one. The former `detectExistingId()` method is gone (folded into
  `mint()`). This only affects a custom `IdMinter` implementation.

### New opt-in algorithms (existing behaviour is unchanged)

A few algorithm choices were added. They are all opt-in, so a profile you carry over keeps signing and
encrypting exactly as before:

- **ECDSA signing.** `SignatureMethod` now has `ECDSA_SHA256`, `ECDSA_SHA384` and `ECDSA_SHA512`. Select one on
  the block with `Outbound\Signature::withSignatureMethod(SignatureMethod::ECDSA_SHA256)`; it needs an EC
  certificate and key. The default stays RSA-SHA256. Inbound, the ECDSA methods are in the default accepted
  signature allow-list, so you can verify an ECDSA-signed response without extra configuration.
- **RSA-OAEP-SHA256 key transport.** The default key transport stays RSA-OAEP with SHA-1, which is
  byte-identical on the wire to before. To upgrade a single block, pass
  `Outbound\Encryption::withKeyTransportAlgorithm(KeyTransportAlgorithm::oaepSha256())`. The named constructors
  are `oaepSha1()`, `oaepSha256()`, `legacyMgf1p()` and `rsa1_5()`. There is no `withOaepHash()` setter; use
  `withKeyTransportAlgorithm()`. Inbound, both SHA-1 and SHA-256 are accepted by default.
- **Inclusive canonicalization.** `SignatureCanonicalization` now has the inclusive Canonical XML 1.0 variants
  `C14N` and `C14N_COMMENTS` alongside the exclusive ones. The exclusive variants remain the default and the
  only form accepted inbound; opt in to an inclusive variant outbound with
  `Outbound\Signature::withCanonicalization(...)` and, if you also verify with it, by adding it to the profile's
  `acceptedCanonicalizations`. Canonical XML 1.1 is not supported.

`SecurityProfile` gained two inbound allow-lists for these: `acceptedOaepHashes` (default SHA-1 and SHA-256) and
`acceptedCanonicalizations` (default the exclusive variants only). Leave them unset to keep the secure defaults.

### One WS-Addressing middleware

`WsaMiddleware2005` is gone. There is now a single `WsaMiddleware` that takes the addressing version as an
argument, and its default namespace is the W3C 2005/08 one. If you relied on the older 2004/08 default, pass
`WsaNamespace::Submission200408` explicitly.

### A couple of smaller changes

- The `withActor()` and `withMustUnderstand()` helpers on the middleware were removed. The blocks now create the security header with safe defaults.
- A response that fails an inbound check throws a single, uniform security error. It does not reveal which step failed, so the middleware cannot be used as an oracle.
