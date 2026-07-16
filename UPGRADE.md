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
new Outbound\Signature($clientCertificate, keyRef: Outbound\KeyRef::BinarySecurityToken);
new Outbound\Encryption($recipientCertificate);
new Inbound\Decrypt($privateKey);
new Inbound\VerifySignature($trustStore, signed: [Part::body(), Part::timestamp()]);
```

If you previously passed engine services into the blocks yourself, you can delete that wiring. Each of those
blocks builds the bundled implementation by default; for the rare case where you need a custom one, override it
with a `with*()` method (`Outbound\Signature::withSigner`, `Outbound\Encryption::withEncryptor`,
`Inbound\Decrypt::withDecryptor`, `Inbound\VerifySignature::withVerifier`) rather than a constructor argument.

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
`KeyRef::Thumbprint`. For encryption, `EncKeyRef` offers the same set. Both live under `WSSecurity\Outbound\`.

Because `Outbound\Signature` takes the optional engine service before the key reference, pass the reference as
a named argument: `new Outbound\Signature($clientCertificate, keyRef: Outbound\KeyRef::BinarySecurityToken)`.

### Algorithm enums moved

The algorithm enums (`SignatureMethod`, `DigestMethod`, `SignatureCanonicalization`, `DataEncryptionMethod`,
`KeyEncryptionMethod`, `KeyTransportAlgorithm`, `OaepHash`) live at the package root under
`Soap\Psr18WsseMiddleware\Algorithm\` — they are W3C XML-Security algorithm identifiers, independent of the SOAP
layer. Update your `use` statements. The defaults are secure on their own, so in most cases you can stop passing
these explicitly.

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
