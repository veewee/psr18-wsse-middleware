# SOAP WSSE/WSA Middleware

This package adds WSSE (WS-Security) and WSA (WS-Addressing) to your PSR-18 based SOAP transport.

From this major version on, the security engine lives inside this package. It signs, encrypts, decrypts and
verifies on top of `ext-openssl` and the modern PHP DOM, so you no longer pull in `robrichards/wse-php` or
`xmlseclibs` at runtime. Because the timestamp parser uses the ICU date formatter, the requirements now also
include `ext-intl`.

# Want to help out? 💚

- [Become a Sponsor](https://github.com/php-soap/.github/blob/main/HELPING_OUT.md#sponsor)
- [Let us do your implementation](https://github.com/php-soap/.github/blob/main/HELPING_OUT.md#let-us-do-your-implementation)
- [Contribute](https://github.com/php-soap/.github/blob/main/HELPING_OUT.md#contribute)
- [Help maintain these packages](https://github.com/php-soap/.github/blob/main/HELPING_OUT.md#maintain)

Want more information about the future of this project? Check out this list of the [next big projects](https://github.com/php-soap/.github/blob/main/PROJECTS.md) we'll be working on.

# Installation

```shell
composer require php-soap/psr18-wsse-middleware
```

This package includes the [php-soap/psr18-transport](https://github.com/php-soap/psr18-transport/) package and is meant to be used together with it.

Requires **PHP 8.4.21+** (or 8.5): signature canonicalization relies on a libxml fix that shipped in 8.4.21, and
`ext-intl` and `ext-openssl` must be enabled. Install `ext-gmp` or `ext-bcmath` for native-speed RSA/ECDSA math.

# How it works

You secure a message by composing building blocks. There are two lists.

The **outbound** list runs on the request you send: it can add a timestamp, attach a token, sign the body,
encrypt a part, and so on. The **inbound** list runs on the response you get back: it can decrypt it, verify
its signature and check its timestamp.

One `SecurityProfile` sits on the `WsseMiddleware`. It is required, and it is the first argument. The profile
carries the shared settings (the algorithm choices, the timestamp window, the inbound accept allow-lists), and
it reaches every block through the per-message context. Blocks that need a setting read it from the profile by
default, and let you override only what you want per block. This means the blocks themselves are clean
one-liners: there is no engine to wire up.

Presence is behaviour. Add a block and that protection is applied. Leave it out and it isn't. The order of the
list is the order things happen in. Sign before you encrypt, decrypt before you verify.

The shape follows the [WS-Security panel in SoapUI](https://www.soapui.org/docs/soapui-projects/ws-security/):
if you have a working SoapUI setup, you can rebuild it here one block at a time.

```php
use Http\Client\Common\PluginClient;
use Soap\Psr18Transport\Psr18Transport;
use Soap\Psr18WsseMiddleware\WsseMiddleware;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound;

$transport = Psr18Transport::createForClient(
    new PluginClient($yourPsr18Client, [
        new WsseMiddleware(
            new SecurityProfile(),
            outbound: [
                new Outbound\Timestamp(),
                // ... add a username, attach a token, sign, encrypt
            ],
            inbound: [
                // ... decrypt, verify the signature, validate the timestamp
            ],
        ),
    ])
);
```

The signing, encryption, decryption and verification blocks are powered by the package's WSSE engine, but you
do not see it: each block builds the engine service it needs with secure defaults. Advanced users who want to
swap an engine service (for example a custom signer) can override it with a `with*()` method; this is
covered once, near the end, under [Custom engine services](#custom-engine-services).

# The building blocks

Every block is a small, immutable value object you drop into the `outbound` or `inbound` list. This section
documents each one: a short example, then every constructor argument and fluent method with its default and
what it expects.

## Outbound: `Timestamp`

Stamps the message with a created/expires window so the receiver can reject a stale or replayed call. It writes
a `wsu:Timestamp` carrying `wsu:Created` (now, UTC) and `wsu:Expires` (now + ttl), and mints a `wsu:Id` on it so
a later `Signature` block can sign the timestamp by reference.

```php
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

new Outbound\Timestamp();        // expires 300 seconds from now
new Outbound\Timestamp(60);      // expires 60 seconds from now
```

- `int $ttl = 300` — seconds from now until the message's `Expires`. Must be a positive integer. Default `300`
  (five minutes). Pick a value that comfortably covers your round trip plus the receiver's clock skew.

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
```

- `string $username` — the username sent in `wsse:Username`. Required.
- `?string $password = null` — the password. Default `null`, which sends a username-only token (no
  `wsse:Password`). Provide a value to send a password.
- `bool $digest = false` — how the password is sent. `false` (default) sends `PasswordText`, the cleartext
  password; the class does not enforce TLS, so only use this over a TLS connection. `true` sends
  `PasswordDigest`: `Base64(SHA1(nonce + created + password))`, with a fresh `wsse:Nonce` and `wsu:Created`, so
  the password never travels in the clear. Digest mode requires a password; combining `digest: true` with no
  password throws.
- `withPassword(string $password): self` — returns a copy with the password set.
- `withDigest(bool $digest): self` — returns a copy with the digest flag set.

## Outbound: `BinarySecurityToken`

Attaches your X.509 certificate as a `wsse:BinarySecurityToken` (base64-DER), so the receiver has the public key
it needs to verify your signature. A `wsu:Id` is minted on the token so a direct reference can point at it.

```php
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

new Outbound\BinarySecurityToken(Certificate::fromFile('security_token.pub'));
```

- `Certificate $certificate` — the public X.509 certificate to embed, as a `KeyStore\Certificate`. Required.

You rarely add this block by hand: the `Signature` block embeds one automatically when you reference the key by
`KeyRef::BinarySecurityToken`. Add it explicitly only when a server expects the token present on its own.

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

- `ClientCertificate $clientCertificate` — the certificate-and-key bundle to sign with. The private key signs;
  the public certificate is advertised in `ds:KeyInfo`. Required.
- `keyRef: KeyRef $keyRef = KeyRef::BinarySecurityToken` — how the certificate is referenced. Pass it as a named
  argument (`keyRef:`). Default `KeyRef::BinarySecurityToken`, the X.509 direct-reference interop default: a
  `wsse:BinarySecurityToken` is embedded and the signature points at it by `wsu:Id`. The other cases
  (`SubjectKeyIdentifier`, `IssuerSerial`, `Thumbprint`) put an inline reference derived from the certificate and
  embed no token. See [Choosing parts and key references](#choosing-parts-and-key-references).
- `withParts(non-empty-list<Part> $parts): self` — which parts to sign. Default is `[Part::body(),
  Part::securityHeaderContents()]`: the Body plus every element currently in the Security header (the Timestamp,
  any tokens), resolved at send time. Because it signs whatever is present, the default never fails when a part
  is absent. Must be a non-empty list of `Part` descriptors. See
  [Choosing parts and key references](#choosing-parts-and-key-references) for the dynamic parts and shortcuts.
- `withSignatureMethod(SignatureMethod $method): self` — the signature algorithm. Default: the profile's
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

  Two legacy cases exist and are **not** accepted inbound by default: `RSA_SHA1` and `DSA_SHA1`. `DSA_SHA1` is
  present because XML Signature 1.1 lists DSAwithSHA1 as a required algorithm for signature *verification*, so
  a peer may still send one; `DSA_SHA1` needs a DSA key to sign with. Use either only for a peer that requires
  it, and add it to `acceptedSignatureMethods` to verify it (see
  [Security profile and defaults](#security-profile-and-defaults)).
- `withDigestMethod(DigestMethod $method): self` — the per-reference digest algorithm. Default: the profile's
  `digestMethod()` (SHA-256). `SHA384` and `SHA512` are also accepted inbound by default. `SHA1` and
  `RIPEMD160` are available but not accepted inbound by default; add them to `acceptedDigestMethods` only for a
  peer that requires them.
- `withCanonicalization(SignatureCanonicalization $canonicalization): self` — the canonicalization method.
  Default: the profile's `canonicalization()` (exclusive C14N). The exclusive variants (`EXC_C14N`,
  `EXC_C14N_COMMENTS`) are the WSSE norm. The inclusive Canonical XML 1.0 variants (`C14N`, `C14N_COMMENTS`)
  are also available for a server that requires them:
  ```php
  use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;

  (new Outbound\Signature($clientCertificate, keyRef: Outbound\KeyReference\KeyRef::BinarySecurityToken))
      ->withCanonicalization(SignatureCanonicalization::C14N);
  ```
  If you sign with an inclusive variant and also verify the response with one, add it to the profile's
  `acceptedCanonicalizations` allow-list as well (see [Security profile and defaults](#security-profile-and-defaults));
  by default only the exclusive variants are accepted inbound.
- `withInclusivePrefixes(): self` — pin the namespace prefixes an exclusive canonicalization would otherwise
  drop, as an `ec:InclusiveNamespaces PrefixList`. Off by default.

  Exclusive C14N deliberately emits only the namespace declarations a subtree visibly uses, which is what lets
  a signature survive being moved into a different envelope. A peer that needs an ancestor's declaration
  anyway — because it resolves a QName out of attribute or text content, or re-serializes the message before
  verifying — cannot get it back unless you pin it. Turn this on for such a peer:
  ```php
  (new Outbound\Signature($clientCertificate))
      ->withInclusivePrefixes();
  ```
  The list is derived per element rather than configured: each signed part pins the prefixes it inherits but
  does not itself use, and `ds:CanonicalizationMethod` pins everything in scope around the Security header.
  That is the same shape a WSS4J peer emits. Nothing changes for the receiver's own checks — the prefix list is
  self-describing, so a verifier reads it from the signature and canonicalizes accordingly. It has no effect on
  an inclusive canonicalization, which already emits every declaration in scope.

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

- `Certificate $recipientCertificate` — the recipient's public certificate, used to wrap the session key.
  Required.
- `encKeyRef: EncKeyRef $encKeyRef = EncKeyRef::SubjectKeyIdentifier` — how the recipient's certificate is
  referenced inside the `xenc:EncryptedKey`, so it knows which private key unwraps the session key. Default
  `EncKeyRef::SubjectKeyIdentifier`. The other cases are `IssuerSerial`, `Thumbprint` and `BinarySecurityToken`.
- `withParts(non-empty-list<Part> $parts): self` — which parts to encrypt. Default is `[Part::body()]`.
- `withDataEncryptionMethod(DataEncryptionMethod $method): self` — the bulk-data cipher. Default: the profile's
  `dataEncryptionMethod()` (AES-256-GCM).
- `withKeyEncryptionMethod(KeyEncryptionMethod $method): self`. The key-transport method that wraps the
  session key. Default: the profile's `keyEncryptionMethod()` (RSA-OAEP). This sets only the method; the OAEP
  hash is resolved from the profile (or its default, SHA-1). To pin the method and the hash together, use
  `withKeyTransportAlgorithm` instead.
- `withKeyTransportAlgorithm(KeyTransportAlgorithm $algorithm): self`. The whole key-transport choice (method
  plus OAEP hash) in one atomic value, so an invalid method/hash pairing cannot be expressed. This override wins
  over both `withKeyEncryptionMethod` and the profile. The default key transport is RSA-OAEP with SHA-1
  (byte-identical on the wire to the previous releases). Select RSA-OAEP-SHA256 when the server expects it:
  ```php
  use Soap\Psr18WsseMiddleware\Algorithm\KeyTransportAlgorithm;

  (new Outbound\Encryption($recipient))
      ->withKeyTransportAlgorithm(KeyTransportAlgorithm::oaepSha256());
  ```
  The named constructors are `KeyTransportAlgorithm::oaepSha1()` (the default), `oaepSha256()`, `legacyMgf1p()`
  (RSA-OAEP-MGF1P, SHA-1) and `rsa1_5()` (RSA-1_5, rejected inbound by default).

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

- `string $assertionXml` — the full `saml:Assertion` element as a well-formed XML string. Required, non-empty.
- `SamlVersion $version` — `SamlVersion::Saml11` or `SamlVersion::Saml20`. Required; the version determines the
  expected namespace and the id attribute (`AssertionID` for 1.1, `ID` for 2.0). The assertion root alone has no
  reliable version discriminant, so you state it.

After it runs, `assertionId()` returns the assertion's id, which advanced Holder-of-Key flows can wire into a
signature through `SamlAssertionKeyIdentifier`:

```php
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\SamlAssertionKeyIdentifier;

new SamlAssertionKeyIdentifier($assertionId, SamlVersion::Saml20);
```

The version is required here too, and for the same reason it is on the block: the SAML Token Profile references
the two versions differently. A SAML 2.0 assertion is named by the 1.1-profile `#SAMLID` value type and the
reference must carry a `wsse11:TokenType` of `#SAMLV2.0`, while a 1.1 assertion keeps the 1.0-profile
`#SAMLAssertionID`. A version-blind reference can only describe a 1.1 assertion.

## Inbound: `Decrypt`

Decrypts the `xenc:EncryptedData` parts of the response with your private key. Each encrypted part is replaced
in place by its plaintext. Place it first in the inbound list, before verification, so the verifier sees the
plaintext.

```php
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound;
use Soap\Psr18WsseMiddleware\KeyStore\Key;

$privateKey = Key::fromFile('security_token.priv')->withPassphrase('xxx');

new Inbound\Decrypt($privateKey);
```

- `Key $privateKey` — your recipient private key as a `KeyStore\Key`. Required.

Any decryption failure collapses to one uniform `SecurityFault` that does not reveal which step failed, so the
middleware cannot be used as a padding oracle.

## Inbound: `VerifySignature`

Verifies the response signature and confirms that the parts you require were actually signed by a trusted
certificate. The verifier reports exactly which nodes a trusted signer covered; this block then asserts your
required parts are in that set, compared by object identity, so a relocated or duplicated look-alike cannot pass
as signed.

```php
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;

$trustStore = TrustStore::fromCertificates(Certificate::fromFile('service-ca.pub'));

new Inbound\VerifySignature(
    $trustStore,
    signed: [Part::body(), Part::timestamp()],
);
```

- `TrustStore $trustStore` — the certificates you trust as signers. Build it with
  `TrustStore::fromCertificates(...)`. Required.
- `signed: list<Part> $signed = []` — the parts that **must** be covered by a trusted signature. Pass it as a
  named argument (`signed:`). Default `[]`, which verifies the signature is valid and trusted but requires no
  particular part to be covered. Name the parts you depend on (typically the body and the timestamp) so an
  attacker cannot strip the signature from the part that matters. The dynamic parts work here too:
  `Part::securityHeaderContents()` requires every token in the Security header to have been signed, and
  `Part::soapHeaders()` requires every other SOAP header block to have been signed.

The accepted signature, digest and canonicalization algorithms come from the profile's allow-lists. By default
the signature allow-list covers RSA and ECDSA at SHA-256/384/512, and only the exclusive C14N variants are
accepted; to accept an inclusive variant, add it to the profile's `acceptedCanonicalizations` (see
[Security profile and defaults](#security-profile-and-defaults)). Every failure cause collapses to one uniform
`SecurityFault` carrying no step-identifying detail, so the block is never a forgery oracle.

The signer's certificate must chain to a trust anchor, be within its validity window, and — if it carries a
`keyUsage` extension — assert either `digitalSignature` or `nonRepudiation` (`contentCommitment`). A
certificate with no `keyUsage` extension is not refused on that ground. No Extended Key Usage is required: the
X.509 Token Profile mandates none, and no registered EKU describes WS-Security message signing.

## Inbound: `ValidateTimestamp`

Rejects a stale or future-dated response before your application sees it. It locates the single `wsu:Timestamp`
in the Security header and asserts the message is not expired, not older than the maximum age, and not stamped
in the future, each within the configured clock skew.

This is not replay detection. There is no nonce cache, so a captured response replayed inside the freshness
window is accepted; what the block does is bound how long that window stays open. Narrow `timestampTtl` and
`clockSkew` to shrink it.

```php
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound;

new Inbound\ValidateTimestamp();
```

- No required arguments. The freshness window (clock skew and maximum age) comes from the `SecurityProfile` on
  the context: `clockSkew()` and `timestampTtl()`. Configure the window on the profile, not on this block.

Dates are parsed strictly: only the exact instant formats a conforming peer emits are accepted. Every failure
collapses to one uniform `SecurityFault`.

# Common flows

The following are complete, copy-pasteable setups. Adapt the file paths, credentials and parts to your service.

## Username/password authentication

The simplest case: a service that just wants a username and a password.

```php
use Http\Client\Common\PluginClient;
use Soap\Psr18Transport\Psr18Transport;
use Soap\Psr18WsseMiddleware\WsseMiddleware;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

$transport = Psr18Transport::createForClient(
    new PluginClient($yourPsr18Client, [
        new WsseMiddleware(
            new SecurityProfile(),
            outbound: [
                new Outbound\Username('your-user', 'your-password'),
                // Prefer a digested password if the server accepts it:
                // (new Outbound\Username('your-user', 'your-password'))->withDigest(true),
            ],
        ),
    ])
);
```

## Signing a request and verifying the response

Sign the request with an X.509 / PKCS#12 certificate, then verify the response is signed by a certificate you
trust and its timestamp is fresh. This is the standard mutual-integrity flow.

```php
use Http\Client\Common\PluginClient;
use Soap\Psr18Transport\Psr18Transport;
use Soap\Psr18WsseMiddleware\WsseMiddleware;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;

// Your signing identity (certificate + private key):
$clientCertificate = ClientCertificate::fromFile('client.pem')->withPassphrase('xxx');

// The certificate you trust on the response signature:
$trustStore = TrustStore::fromCertificates(Certificate::fromFile('service-ca.pub'));

$transport = Psr18Transport::createForClient(
    new PluginClient($yourPsr18Client, [
        new WsseMiddleware(
            new SecurityProfile(),
            outbound: [
                new Outbound\Timestamp(),
                new Outbound\Signature(
                    $clientCertificate,
                    keyRef: Outbound\KeyReference\KeyRef::BinarySecurityToken,
                ),
                // The default already signs the Body and the Security-header contents. To be explicit:
                // (new Outbound\Signature($clientCertificate, keyRef: Outbound\KeyReference\KeyRef::BinarySecurityToken))
                //     ->withParts([Part::body(), Part::securityHeaderContents()]),
            ],
            inbound: [
                new Inbound\VerifySignature(
                    $trustStore,
                    signed: [Part::body(), Part::timestamp()],
                ),
                new Inbound\ValidateTimestamp(),
            ],
        ),
    ])
);
```

Starting from a `.p12` / `.pfx` file? Load it directly, no PEM conversion needed. The passphrase decrypts the
file; the extracted private key is returned ready to use.

```php
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\KeyStore\Pkcs12Bundle;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;

// Decode the .p12 once, then derive each credential from the bundle:
$bundle = Pkcs12Bundle::fromFile('client.p12', 'secret');

// Your signing identity (certificate + private key):
$clientCertificate = ClientCertificate::fromPkcs12($bundle);
new Outbound\Signature($clientCertificate, keyRef: Outbound\KeyReference\KeyRef::BinarySecurityToken);

// A recipient / BinarySecurityToken certificate from its own .p12:
$recipient = Certificate::fromPkcs12(Pkcs12Bundle::fromFile('service.p12', 'secret'));

// The trust anchors from the CA chain embedded in the .p12:
$trustStore = TrustStore::fromPkcs12(Pkcs12Bundle::fromFile('service.p12', 'secret'));
```

`Pkcs12Bundle::fromFile()` reads the file for you; `Pkcs12Bundle::fromString()` takes the raw bytes instead.
Decode the bundle once and pass it to `Certificate`, `ClientCertificate` and `TrustStore::fromPkcs12()`, so the
blob is parsed a single time. `TrustStore::fromPkcs12()` builds its anchors from the CA chain embedded in the
bundle (the `extracerts`), so it throws if the bundle embeds no chain. To keep using separate PEM files, see
`Certificate::fromFile(...)`, `Key::fromFile(...)` and `ClientCertificate::fromFile(...)` under
[Key stores](#key-stores).

## SAML assertion flow

A SAML flow has two steps. First you obtain an assertion from a Security Token Service (STS), which typically
means signing a request to the STS. Then you attach the returned assertion to your real service call and sign
that call too.

```php
use Http\Client\Common\PluginClient;
use Soap\Psr18Transport\Psr18Transport;
use Soap\Psr18WsseMiddleware\WsseMiddleware;
use Soap\Psr18WsseMiddleware\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;

$clientCertificate = ClientCertificate::fromFile('client.pem')->withPassphrase('xxx');

// Step 1 — fetch an assertion from the STS by signing the request to it.
$stsTransport = Psr18Transport::createForClient(
    new PluginClient($yourPsr18Client, [
        new WsseMiddleware(
            new SecurityProfile(),
            outbound: [
                new Outbound\Timestamp(),
                new Outbound\Signature($clientCertificate, keyRef: Outbound\KeyReference\KeyRef::BinarySecurityToken),
            ],
        ),
    ])
);

// Call the STS through $stsTransport, then pull the <saml:Assertion> element out of the
// response and keep it as an XML string:
$assertionXml = /* the full <saml:Assertion> ... </saml:Assertion> string from the STS response */;

// Step 2 — attach the assertion to your real service call and sign that call.
$serviceTransport = Psr18Transport::createForClient(
    new PluginClient($yourPsr18Client, [
        new WsseMiddleware(
            new SecurityProfile(),
            outbound: [
                new Outbound\Timestamp(),
                new Outbound\SamlAssertion(
                    $assertionXml,
                    Outbound\SamlVersion::Saml20,
                ),
                new Outbound\Signature($clientCertificate, keyRef: Outbound\KeyReference\KeyRef::BinarySecurityToken),
            ],
        ),
    ])
);
```

## Encrypting a request and decrypting the response

Encrypt sensitive parts on the way out and decrypt them on the way back. In practice you combine this with
signing: sign first, then encrypt outbound; decrypt first, then verify inbound.

```php
use Http\Client\Common\PluginClient;
use Soap\Psr18Transport\Psr18Transport;
use Soap\Psr18WsseMiddleware\WsseMiddleware;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;

$clientCertificate = ClientCertificate::fromFile('client.pem')->withPassphrase('xxx');
$recipient = Certificate::fromFile('service.pub');          // who we encrypt to
$ourPrivateKey = Key::fromFile('security_token.priv')->withPassphrase('xxx'); // who decrypts the reply
$trustStore = TrustStore::fromCertificates(Certificate::fromFile('service-ca.pub'));

$transport = Psr18Transport::createForClient(
    new PluginClient($yourPsr18Client, [
        new WsseMiddleware(
            new SecurityProfile(),
            outbound: [
                new Outbound\Timestamp(),
                // Sign first ...
                new Outbound\Signature($clientCertificate, keyRef: Outbound\KeyReference\KeyRef::BinarySecurityToken),
                // ... then encrypt:
                new Outbound\Encryption($recipient),
            ],
            inbound: [
                // Decrypt first ...
                new Inbound\Decrypt($ourPrivateKey),
                // ... then verify and check freshness:
                new Inbound\VerifySignature($trustStore, signed: [Part::body(), Part::timestamp()]),
                new Inbound\ValidateTimestamp(),
            ],
        ),
    ])
);
```

# Key stores

The package wraps your keys and certificates in small value objects:

- `KeyStore\Certificate`: a public X.509 certificate in PEM format.
- `KeyStore\Key`: a private key (PKCS#8) in PEM format.
- `KeyStore\ClientCertificate`: a certificate and a private key together in one PEM bundle.

```php
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;

$privateKey = Key::fromFile('security_token.priv')->withPassphrase('xxx');
$certificate = Certificate::fromFile('security_token.pub');

// Or load both from a single bundle:
$bundle = ClientCertificate::fromFile('client.pem')->withPassphrase('xxx');
$privateKey = $bundle->privateKey();          // returns a KeyStore\Key
$certificate = $bundle->publicCertificate();  // returns a KeyStore\Certificate
```

- `Key::fromFile(string $file): Key` then `->withPassphrase(string): Key` if the key is encrypted.
- `Certificate::fromFile(string $file): Certificate`.
- `ClientCertificate::fromFile(string $file): ClientCertificate` then `->withPassphrase(string)`; it exposes
  `->privateKey(): Key` and `->publicCertificate(): Certificate`.

Got a `.p12` / `.pfx` file? Load it directly, no conversion needed. The passphrase decrypts the file; the
extracted private key is returned ready to use, so no `->withPassphrase(...)` follows.

```php
use Soap\Psr18WsseMiddleware\KeyStore\Pkcs12Bundle;

// Decode the .p12 once:
$p12 = Pkcs12Bundle::fromFile('client.p12', 'secret');

// Certificate + key bundle, ready to sign with:
$clientCertificate = ClientCertificate::fromPkcs12($p12);

// Just the leaf certificate (recipient / BinarySecurityToken):
$certificate = Certificate::fromPkcs12(Pkcs12Bundle::fromFile('service.p12', 'secret'));

// Trust anchors from the CA chain embedded in the file:
$trustStore = TrustStore::fromPkcs12(Pkcs12Bundle::fromFile('service.p12', 'secret'));
```

- `Pkcs12Bundle::fromFile(string $file, string $passphrase = ''): Pkcs12Bundle` decodes the blob (or
  `Pkcs12Bundle::fromString(string $contents, ...)` for raw bytes). Decode once.
- `ClientCertificate::fromPkcs12(Pkcs12Bundle): ClientCertificate`, `Certificate::fromPkcs12(Pkcs12Bundle)` and
  `TrustStore::fromPkcs12(Pkcs12Bundle)` derive each credential from the decoded bundle.
- `TrustStore::fromPkcs12()` builds its anchors from the CA chain embedded in the bundle (the `extracerts`); it
  throws if the bundle embeds no chain.
- A wrong passphrase or a file that is not a PKCS#12 throws a `Pkcs12Exception` with a generic message.

# Choosing parts and key references

A few value objects let you say which parts to protect and how a token is referenced.

`Part` names the parts a block targets:

- `Part::body()` — the SOAP Body.
- `Part::timestamp()` — the `wsu:Timestamp` in the Security header (add a `Timestamp` block to produce one).
- `Part::element(string $namespace, string $localName)` — a specific element by qualified name.
- `Part::byId(string $id)` — an element by its `wsu:Id`.
- `Part::usernameToken()` / `Part::binarySecurityToken()` — shortcuts for the `wsse:UsernameToken` and
  `wsse:BinarySecurityToken` in the Security header (equivalent to `Part::element()` with the WS-Security namespace).

Two **dynamic** parts are expanded against the live message rather than naming one element — the equivalents of
RobRichards `wse-php`'s header signing. They work in both directions: outbound the Signature block signs every
element they expand to; inbound `VerifySignature` requires every such element to have been signed.

- `Part::securityHeaderContents()` — every element currently in the `wsse:Security` header (the Timestamp, any
  tokens; the `ds:Signature` itself is excluded). This is part of the signing default.
- `Part::soapHeaders()` — every SOAP header block **except** the `wsse:Security` header itself (for example
  WS-Addressing headers). Opt in with `withParts([Part::body(), Part::securityHeaderContents(), Part::soapHeaders()])`.

`KeyRef` (for signing) and `EncKeyRef` (for encryption) choose how your certificate is referenced:

- `Outbound\KeyReference\KeyRef`: `BinarySecurityToken` (embed the token and point at it; the X.509 interop default for
  signing), `SubjectKeyIdentifier`, `IssuerSerial`, `Thumbprint`.
- `Outbound\KeyReference\EncKeyRef`: `SubjectKeyIdentifier` (the default for encryption), `IssuerSerial`, `Thumbprint`,
  `BinarySecurityToken`.

`KeyStore\TrustStore::fromCertificates(Certificate ...$anchors)` lists the certificates you trust when verifying a
response.

# Security profile and defaults

You configure a `SecurityProfile` once on the `WsseMiddleware` and it reaches every block through the
per-message context. Outbound blocks read their algorithm choices and the timestamp window from it (and let you
override per block); inbound blocks read the accept allow-lists and the freshness window from it.

```php
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\KeyEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;

// Secure defaults — equivalent to SecurityProfile::default():
$profile = new SecurityProfile();

// A fully spelled-out profile: the WS-Security timestamp window plus an XML-Security CryptoPolicy that
// carries the algorithm choices and the inbound accept allow-lists.
$profile = new SecurityProfile(
    timestampTtl: 300,
    clockSkew: 60,
    crypto: new CryptoPolicy(
        signatureMethod: SignatureMethod::RSA_SHA256,
        digestMethod: DigestMethod::SHA256,
        canonicalization: SignatureCanonicalization::EXC_C14N,
        dataEncryptionMethod: DataEncryptionMethod::AES256_GCM,
        keyEncryptionMethod: KeyEncryptionMethod::RSA_OAEP,
    ),
);
```

`SecurityProfile` carries the WS-Security freshness window, how the Security header is targeted, and composes a
`CryptoPolicy`:

- `int $timestampTtl = 300` — the outbound timestamp window in seconds, and the maximum accepted age of an
  inbound timestamp.
- `int $clockSkew = 60` — the tolerance, in seconds, applied when checking an inbound timestamp against the
  local clock.
- `?CryptoPolicy $crypto = null` — the XML-Security algorithm policy below; `null` uses `CryptoPolicy::default()`.
- `?string $actorOrRole = null` — which hop this exchange belongs to, spelled `soap:actor` in SOAP 1.1 and
  `soap:role` in SOAP 1.2. `null` (default) means the ultimate receiver, whose header carries no such attribute.

  One value does both jobs, because both answer the same question. Outbound it targets the header the blocks
  write into; inbound it selects the header they read, so a signature or timestamp in a header addressed to a
  different hop is not treated as yours. Set it only if your deployment is addressed as a named intermediary:

  ```php
  $profile = new SecurityProfile(actorOrRole: 'urn:my-gateway');
  ```
- `bool $mustUnderstand = true` — whether the outbound Security header demands the receiver process it or
  fault. Leave it on unless a peer rejects the attribute.

`CryptoPolicy` (namespace `Soap\Psr18WsseMiddleware\XmlSecurity`) carries the algorithm choices and allow-lists,
and can be used to drive the signing/encryption engine without the SOAP profile:

- `SignatureMethod $signatureMethod = SignatureMethod::RSA_SHA256` — the outbound signature algorithm.
- `DigestMethod $digestMethod = DigestMethod::SHA256` — the outbound per-reference digest.
- `SignatureCanonicalization $canonicalization = SignatureCanonicalization::EXC_C14N` — the outbound
  canonicalization method.
- `DataEncryptionMethod $dataEncryptionMethod = DataEncryptionMethod::AES256_GCM` — the outbound bulk cipher.
- `KeyEncryptionMethod $keyEncryptionMethod = KeyEncryptionMethod::RSA_OAEP` — the outbound key-transport
  algorithm.
- `?array $acceptedSignatureMethods = null` — the inbound allow-list for signature algorithms. `null` (default)
  applies secure defaults: RSA-SHA256/384/512 and ECDSA-SHA256/384/512, rejecting SHA-1 and HMAC methods.
- `?array $acceptedDigestMethods = null` — the inbound allow-list for digests. Default: SHA-256/384/512.
- `?array $acceptedKeyEncryptionMethods = null` — the inbound allow-list for key transport. Default: RSA-OAEP and
  RSA-OAEP-MGF1P, rejecting RSA-1_5.
- `?array $acceptedDataEncryptionMethods = null` — the inbound allow-list for bulk ciphers. Default: AES-GCM and
  AES-CBC at 128/192/256, rejecting 3DES. The CBC ciphers are accepted because peers commonly send them, but
  only the GCM ciphers authenticate their own ciphertext, and this library does not require an encrypted part
  to also be covered by a verified signature. If your peer can encrypt with GCM, narrow the list and get
  authenticated encryption guaranteed rather than assumed:
  ```php
  use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;

  $profile = new SecurityProfile(crypto: new CryptoPolicy(
      acceptedDataEncryptionMethods: [
          DataEncryptionMethod::AES128_GCM,
          DataEncryptionMethod::AES192_GCM,
          DataEncryptionMethod::AES256_GCM,
      ],
  ));
  ```
- `?array $acceptedOaepHashes = null` — the inbound allow-list for the OAEP hash on an inbound `EncryptedKey`.
  Default: SHA-1 and SHA-256.
- `?array $acceptedCanonicalizations = null` — the inbound allow-list for the canonicalization on an inbound
  signature. Default: the exclusive variants only (`SignatureCanonicalization::EXC_C14N` and
  `EXC_C14N_COMMENTS`). The inclusive variants are not the WSSE norm, so accepting them only widens the attack
  surface; opt in by listing `SignatureCanonicalization::C14N` and/or `C14N_COMMENTS` here:
  ```php
  use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;

  $profile = new SecurityProfile(crypto: new CryptoPolicy(
      acceptedCanonicalizations: [
          SignatureCanonicalization::EXC_C14N,
          SignatureCanonicalization::EXC_C14N_COMMENTS,
          SignatureCanonicalization::C14N,
      ],
  ));
  ```
  This is also what a peer whose `ds:Reference` elements carry no `ds:Transforms` needs. XML-DSig digests such
  a reference under inclusive canonicalization — `ds:SignedInfo`'s own `CanonicalizationMethod` covers only
  `ds:SignedInfo` — so with the exclusive-only default those signatures are refused. Listing
  `SignatureCanonicalization::C14N` above is the supported way to verify them.

The defaults reject weak algorithms (SHA-1, RSA-1_5, 3DES) and use SHA-256 with exclusive canonicalization. The
algorithm enums live under `Soap\Psr18WsseMiddleware\Algorithm\`: `SignatureMethod`, `DigestMethod`,
`SignatureCanonicalization`, `DataEncryptionMethod`, `KeyEncryptionMethod`, `KeyTransportAlgorithm` and
`OaepHash`.

## Supported algorithms and limitations

- **Signatures:** RSA-SHA256/384/512 and ECDSA-SHA256/384/512. RSA-SHA1 is rejected by default. ECDSA needs an
  EC certificate and key.
- **Digests:** SHA-256/384/512. SHA-1 is rejected by default.
- **Key transport:** RSA-OAEP-SHA1 (the default, byte-identical to previous releases), RSA-OAEP-SHA256,
  RSA-OAEP-MGF1P and RSA-1_5 (rejected by default). Select a non-default with
  `Outbound\Encryption::withKeyTransportAlgorithm(...)`.
- **Bulk encryption:** AES-GCM and AES-CBC at 128/192/256 bits. 3DES is rejected by default.
- **Canonicalization:** exclusive C14N (`EXC_C14N`, `EXC_C14N_COMMENTS`) is the default and the only form
  accepted inbound unless you opt in. Inclusive Canonical XML 1.0 (`C14N`, `C14N_COMMENTS`) is supported as an
  opt-in. Canonical XML 1.1 is **not** supported: the underlying platform does not provide it.

## Limits on an inbound message

Every parse rejects a DOCTYPE declaration before any block runs, which removes external entities and entity
expansion as an attack surface. Beyond that the middleware relies on the parser's own default limits — it never
asks for the "huge" parse mode that lifts them — so an inbound response is refused once it nests deeper than
256 elements.

Note what that does **not** cover: the parser does not bound the length of an individual text node, and there
is deliberately no total message-size cap here. The response body is already fully in memory by the time a
PSR-18 middleware sees it, so a cap at this layer would only bound parsing cost against a server you chose to
call. Cap the body at the HTTP client if you need one.

- **References per signature:** a `ds:SignedInfo` may declare at most 32 `ds:Reference` entries. A small
  message declaring an absurd number of references would otherwise amplify canonicalization and digest work
  far beyond its own size, which a size limit could not bound.

# WsaMiddleware

If your server expects WS-Addressing headers, add the WSA middleware. It is one configurable middleware that
covers both addressing versions, and it defaults to the W3C 2005/08 namespace.

```php
use Http\Client\Common\PluginClient;
use Soap\Psr18Transport\Psr18Transport;
use Soap\Psr18WsseMiddleware\WsaMiddleware;
use Soap\Psr18WsseMiddleware\Wsa\WsaNamespace;
use Soap\Psr18WsseMiddleware\Wsa\WsaOptions;

$transport = Psr18Transport::createForClient(
    new PluginClient($yourPsr18Client, [
        new WsaMiddleware(),
        // Or pick the addressing version explicitly:
        // new WsaMiddleware(new WsaOptions(WsaNamespace::Submission200408)),
        // Or set a non-anonymous ReplyTo address:
        // new WsaMiddleware(new WsaOptions(replyTo: 'https://your-app.example/reply')),
        // Or send faults somewhere other than the reply address:
        // new WsaMiddleware(new WsaOptions(faultTo: 'https://your-app.example/faults')),
    ])
);
```

Everything is configured through `WsaOptions`. Every property is optional, because each one has a sensible
answer without configuration — the default `new WsaOptions()` produces the headers a service expects:

- `WsaNamespace $namespace = WsaNamespace::W3c200508` — the addressing version. `WsaNamespace::W3c200508`
  (default) is the W3C 2005/08 namespace; `WsaNamespace::Submission200408` is the older 2004/08 submission
  namespace.
- `?string $action = null` — the `wsa:Action`. Default `null`, which uses the request's `SOAPAction`.
- `?string $to = null` — the `wsa:To`. Default `null`, which uses the request URI.
- `?string $replyTo = null` — the `wsa:ReplyTo` address. Default `null`, which uses the version's
  anonymous URI.
- `?string $from = null` — the `wsa:From` address. Default `null`, which omits the header.
- `?string $faultTo = null` — the `wsa:FaultTo` address, where the service sends a fault instead of to
  `ReplyTo`. Default `null`, which omits the header so faults follow `ReplyTo`.

`wsa:MessageID` is always freshly generated and is not configurable: the receiver echoes it back in
`wsa:RelatesTo` to correlate the reply, and a reused value would break that correlation. `wsa:RelatesTo`
itself is a reply property, so it is not an outbound option; `WsaHeader::withRelatesTo()` remains available
if you build a header directly.

It fills in `Action` (from the SOAP action), `To` (from the request URI), a generated `MessageID`, and
`ReplyTo`.

# Custom engine services

The signing, encryption, decryption and verification blocks build the engine service they need with secure
defaults, so you normally pass nothing extra. If you need to customize the engine, override the bundled service
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
