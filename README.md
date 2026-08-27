# SOAP WSSE/WSA Middleware

This package adds WSSE (WS-Security) and WSA (WS-Addressing) to your PSR-18 based SOAP transport.

Signing, encryption, decryption and verification all happen inside this package, on the modern PHP DOM. There is
no XML-security library behind it. The cryptography underneath is split, which is worth knowing if you scope a
CVE watch by dependency: `phpseclib/phpseclib` does the symmetric ciphers, the RSA and ECDSA signatures and the
RSA key transport, `ext-openssl` does certificate path validation and key parsing, and digests run on `ext-hash`.
The inbound timestamp parser reads instants with the ICU date formatter, which is why `ext-intl` is required.

Coming from 3.x? Read the [upgrade guide](UPGRADE.md) first: the block names, the credential objects and several
defaults are different.

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

Requires **PHP 8.4.21** or newer, because signature canonicalization relies on a libxml fix that shipped in that
patch release, with `ext-intl` and `ext-openssl` enabled. Install `ext-gmp` or `ext-bcmath` for native-speed RSA/ECDSA math.

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
    ])
);
```

The default `new WsaOptions()` produces the headers a service expects: it fills in `Action` (from the SOAP
action), `To` (from the request URI), a freshly generated `MessageID`, and an anonymous `ReplyTo`. Every
property is optional; see [WsaMiddleware](docs/wsa-middleware.md) for all of them.

# WsseMiddleware

## How it works

You secure a message by composing building blocks. There are two lists.

The **outbound** list runs on the request you send: it can add a timestamp, attach a token, sign the body,
encrypt a part, and so on. The **inbound** list runs on the response you get back: it can decrypt it, verify
its signature and check its timestamp.

One `SecurityProfile` sits on the `WsseMiddleware`. It is required, and it is the first argument. The profile
carries the shared settings (the algorithm choices, the timestamp window, the inbound accept allow-lists), and
it reaches every block through the per-message context. Blocks that need a setting read it from the profile by
default, and let you override only what you want per block. This means the blocks themselves are clean
one-liners: there is nothing to wire up.

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
                // ... Add a username, attach a token, sign, encrypt
            ],
            inbound: [
                // ... Decrypt, verify the signature, validate the timestamp
            ],
        ),
    ])
);
```

The signing, encryption, decryption and verification blocks are powered by the package's XML-Security layer,
but you do not see it: each block builds the engine service it needs with secure defaults. Advanced users who
want to swap an engine service (for example a custom signer) can override it with a `with*()` method, covered under
[Custom engine services](docs/xmlsecurity.md#custom-engine-services).

## Deep dives

The rest of this README gets you a working setup. When you need the exact arguments, or the reasoning behind a
default you are about to change, drop one level down:

| Take a closer look at | For |
|---|---|
| [Outbound blocks](docs/outbound-blocks.md) | Every argument and `with*()` method of `Timestamp`, `Username`, `BinarySecurityToken`, `Signature`, `Encryption`, `SamlAssertion` |
| [Inbound blocks](docs/inbound-blocks.md) | The same for `ResolveOptimizedBytes`, `Decrypt`, `VerifySignature`, `ValidateTimestamp`, and what a `soap:Fault` reply gives you |
| [Choosing parts and key references](docs/parts-and-key-references.md) | `Part`, the dynamic parts, `KeyRef` and `EncKeyRef` |
| [Key stores](docs/key-stores.md) | Loading certificates, private keys, PEM bundles and `.p12` / `.pfx` files |
| [Trust](docs/trust.md) | Why a verified signature is not an authenticated peer, pinning, and opt-in revocation checking |
| [Security profile and defaults](docs/security-profile.md) | `SecurityProfile`, `CryptoPolicy`, the inbound allow-lists, and what is rejected by default and why |
| [The XML-Security layer](docs/xmlsecurity.md) | Swapping an engine service, and signing or encrypting plain XML without SOAP |
| [Attachment security](docs/attachments.md) | Signing and encrypting SOAP attachments (SwA and MTOM), cipher bytes travelling in MIME parts, how much of a part a protection covers, the wire format, and what is refused |
| [Importing a peer's existing configuration](docs/importing-a-peer-configuration.md) | Turning a SoapUI project or an IBM WebSphere descriptor you were handed into these blocks |

## The building blocks

Every block is a small, immutable value object you drop into the `outbound` or `inbound` list.

| Outbound | Adds |
|---|---|
| [`Timestamp`](docs/outbound-blocks.md#outbound-timestamp) | A `wsu:Timestamp` so the receiver can reject a stale or replayed call |
| [`Username`](docs/outbound-blocks.md#outbound-username) | A `wsse:UsernameToken`, with a plaintext or digested password |
| [`BinarySecurityToken`](docs/outbound-blocks.md#outbound-binarysecuritytoken) | Your X.509 certificate as a base64-DER token |
| [`Signature`](docs/outbound-blocks.md#outbound-signature) | A detached, multi-reference `ds:Signature`, keyed by a certificate or a shared secret, optionally covering attachments and their MIME headers |
| [`Encryption`](docs/outbound-blocks.md#outbound-encryption) | XML-Enc ciphertext for the parts you name, and optionally the attachments, under a session key a key source provides |
| [`SamlAssertion`](docs/outbound-blocks.md#outbound-samlassertion) | A SAML 1.1 / 2.0 assertion you obtained from an STS |

| Inbound | Checks |
|---|---|
| [`ResolveOptimizedBytes`](docs/inbound-blocks.md#inbound-resolveoptimizedbytes) | Puts back cipher bytes a peer moved into MIME parts, which CXF with MTOM and .NET do by default |
| [`Decrypt`](docs/inbound-blocks.md#inbound-decrypt) | Decrypts the `xenc:EncryptedData` parts, and optionally the attachments, with your private key |
| [`VerifySignature`](docs/inbound-blocks.md#inbound-verifysignature) | The signature verifies, and the parts and attachments you require were covered by a trusted signer (including a token covered through `#STR-Transform`) |
| [`ValidateTimestamp`](docs/inbound-blocks.md#inbound-validatetimestamp) | The response is not stale, future-dated, or past its own `Expires` |

### The order to list them in

Blocks run in the order you write them, and the order is part of your security policy. Nothing inspects the
list you compose, so these are yours to get right:

- **Outbound:** `Timestamp`, then the tokens (`Username`, `BinarySecurityToken`, `SamlAssertion`), then
  `Signature`, then `Encryption`. Signing before encrypting is what lets the receiver verify the signature over
  the plaintext it will read.
- **Inbound:** `ResolveOptimizedBytes` (only if you registered it), then `Decrypt`, then `VerifySignature`,
  then `ValidateTimestamp`. Verifying before decrypting fails
  closed against an encrypt-then-sign peer, so that mistake breaks loudly rather than silently.
- **An empty `inbound` list checks nothing.** A client that signs every request and accepts any response at all
  is a valid configuration as far as this middleware is concerned. If you sign outbound, verify inbound.
- **`ValidateTimestamp` needs a signed timestamp.** `VerifySignature` requires the body by default but nothing
  more, so name `Part::timestamp()` too.
- **An endorsing `Signature` goes last**, after the block it endorses. It covers that block's signature, so a
  header with nothing to endorse, or with two candidates, is refused rather than signed over.

## Common flows

The following are complete, copy-pasteable setups. Adapt the file paths, credentials and parts to your service.

| Flow | Reach for it when |
|---|---|
| [Username/password authentication](#usernamepassword-authentication) | The service just wants credentials, and you are on TLS |
| [Signing a request and verifying the response](#signing-a-request-and-verifying-the-response) | You have a certificate and want mutual integrity. The standard case |
| [SAML assertion flow](#saml-assertion-flow) | An STS issues you an assertion to present |
| [Encrypting a request and decrypting the response](#encrypting-a-request-and-decrypting-the-response) | Part of the message is confidential, not just tamper-evident |
| [Symmetric binding: a secret you and your peer already share](#symmetric-binding-a-secret-you-and-your-peer-already-share) | An `sp:SymmetricBinding` and you already hold a shared secret |
| [Symmetric binding: one session key for the signature and the encryption](#symmetric-binding-one-session-key-for-the-signature-and-the-encryption) | An `sp:SymmetricBinding` and you have only their certificate |

If you are new here, read the first two in order. The rest are self-contained.

### Username/password authentication

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
                // (new Outbound\Username('your-user', 'your-password'))->withNonce(true)->withCreated(true),
            ],
        ),
    ])
);
```

### Signing a request and verifying the response

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
use Soap\Psr18WsseMiddleware\WSSecurity\Signing;
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
                new Outbound\Signature(new Signing\Asymmetric(
                    $clientCertificate,
                    Outbound\KeyReference\KeyRef::BinarySecurityToken,
                )),
                // The default already signs the Body and the Security-header contents. To be explicit:
                // (new Outbound\Signature(new Signing\Asymmetric($clientCertificate)))
                //     ->withParts([Part::body(), Part::securityHeaderContents()]),
            ],
            inbound: [
                new Inbound\VerifySignature($trustStore,
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
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Signing;

// Decode the .p12 once, then derive each credential from the bundle:
$bundle = Pkcs12Bundle::fromFile('client.p12', 'secret');

// Your signing identity (certificate + private key):
$clientCertificate = ClientCertificate::fromPkcs12($bundle);
new Outbound\Signature(new Signing\Asymmetric($clientCertificate));

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
[Key stores](docs/key-stores.md).

Handed a trusted-CA file instead, with several certificates concatenated into one PEM and no private key? Load
it as a PEM bundle, where every certificate becomes a trust anchor:

```php
use Soap\Psr18WsseMiddleware\KeyStore\Pem;

$trustStore = TrustStore::fromPem(Pem::fromFile('anchors.pem'));
```

Use this rather than `TrustStore::fromPkcs12()` for a trusted-CA file or a converted Java truststore: `fromPem()`
keeps every certificate, while `fromPkcs12()` treats entry 0 as the leaf certificate of a signing identity and
skips it. See [Key stores](docs/key-stores.md) for the details.

### SAML assertion flow

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
use Soap\Psr18WsseMiddleware\WSSecurity\Signing;

$clientCertificate = ClientCertificate::fromFile('client.pem')->withPassphrase('xxx');

// Step 1. Fetch an assertion from the STS by signing the request to it.
$stsTransport = Psr18Transport::createForClient(
    new PluginClient($yourPsr18Client, [
        new WsseMiddleware(
            new SecurityProfile(),
            outbound: [
                new Outbound\Timestamp(),
                new Outbound\Signature(new Signing\Asymmetric($clientCertificate)),
            ],
        ),
    ])
);

// Call the STS through $stsTransport, then pull the <saml:Assertion> element out of the
// response and keep it as an XML string:
$assertionXml = /* the full <saml:Assertion> ... </saml:Assertion> string from the STS response */;

// Step 2. Attach the assertion to your real service call and sign that call.
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
                new Outbound\Signature(new Signing\Asymmetric($clientCertificate)),
            ],
        ),
    ])
);
```

### Encrypting a request and decrypting the response

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
use Soap\Psr18WsseMiddleware\WSSecurity\Keys;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\Signing;
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
                new Outbound\Signature(new Signing\Asymmetric($clientCertificate)),
                // ... Then encrypt:
                new Outbound\Encryption(new Keys\GeneratedSessionKey($recipient)),
            ],
            inbound: [
                // Decrypt first ...
                new Inbound\Decrypt($ourPrivateKey),
                // ... Then verify and check freshness:
                new Inbound\VerifySignature($trustStore, signed: [Part::body(), Part::timestamp()]),
                new Inbound\ValidateTimestamp(),
            ],
        ),
    ])
);
```

### Symmetric binding: a secret you and your peer already share

The other way to key a symmetric binding, and the one worth reaching for first when you have the choice. Nothing
about the key goes on the wire: both sides already hold it, so the message carries only a reference naming which
of the agreed keys it used.

That is what makes this the symmetric case that actually authenticates, and mutually: only the two holders of the
secret can produce a MAC that verifies under it. So there is no endorsing signature here, and no certificate at
all. What it does not give you is non-repudiation, since either side could have produced any given message.

```php
use Http\Client\Common\PluginClient;
use Soap\Psr18Transport\Psr18Transport;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\Signing;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsSecurityValueType;
use Soap\Psr18WsseMiddleware\WsseMiddleware;

// The secret itself: raw key bytes, from wherever your deployment keeps them. 32 bytes here, because
// AES-256-GCM takes exactly that width and HMAC-SHA256 carries its full strength at it.
$secret = SessionKey::fromBytes(base64_decode($config['wsse_shared_secret'], true));

// One source, held by every block in both directions. The identifier is the name you and your peer agreed on
// out of band, and it is carried verbatim, so it has to be base64 under the default encoding.
$sharedSecret = new Keys\PreSharedSessionKey(
    $secret,
    base64_encode('our-agreed-key-name'),
    WsSecurityValueType::EncryptedKeySha1->value,
);

$transport = Psr18Transport::createForClient(
    new PluginClient($yourPsr18Client, [
        new WsseMiddleware(
            new SecurityProfile(),
            outbound: [
                new Outbound\Timestamp(),
                (new Outbound\Signature(new Signing\Symmetric($sharedSecret)))
                    ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
                    ->withParts([Part::body(), Part::timestamp()]),
                (new Outbound\Encryption($sharedSecret))
                    ->withParts([Part::body()]),
            ],
            inbound: [
                // The same source both ways. No private key to unwrap with, and no trust store, because no
                // certificate is involved in either direction.
                new Inbound\Decrypt(preSharedKey: $sharedSecret),
                new Inbound\VerifySignature(
                    preSharedKey: $sharedSecret,
                    signed: [Part::body(), Part::timestamp()],
                ),
                new Inbound\ValidateTimestamp(),
            ],
        ),
    ])
);
```

Which `ValueType` to agree on depends on the peer. A WSS4J or CXF one wants the WSS 1.1 `EncryptedKeySHA1` URI
used above, because that is the only custom identifier its emitter writes for a shared secret. Nothing here is a
digest of any cipher bytes, and it does not have to be: the URI names the shape of the reference rather than how
the value was arrived at. Their reader takes any type at all, so a peer that is something else is free to agree
on another. See [`PreSharedSessionKey`](docs/outbound-blocks.md#presharedsessionkey) for the arguments, and
[Session keys](docs/key-stores.md#session-keys) for where the bytes come from and why they have to be a key
rather than a passphrase.

### Symmetric binding: one session key for the signature and the encryption

What an `sp:SymmetricBinding` policy asks for. Both blocks are handed the **same** key source, which is how they
come to share one `xenc:EncryptedKey`; the endorsing signature at the end is what makes the request authenticate
anybody at all, because a session key wrapped under the server's public certificate proves possession of nothing.

```php
use Http\Client\Common\PluginClient;
use Soap\Psr18Transport\Psr18Transport;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\EncKeyRef;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\KeyRef;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\Signing;
use Soap\Psr18WsseMiddleware\WsseMiddleware;

$clientCertificate = ClientCertificate::fromFile('client.pem')->withPassphrase('xxx');
$recipient = Certificate::fromFile('service.pub');
$trustStore = TrustStore::fromCertificates(Certificate::fromFile('service-ca.pub'));

// One session key, shared by being the same object. Add a Keys\DerivedSessionKey per block when the policy
// asks for sp:RequireDerivedKeys.
$sessionKey = new Keys\GeneratedSessionKey($recipient, EncKeyRef::Thumbprint);

$transport = Psr18Transport::createForClient(
    new PluginClient($yourPsr18Client, [
        new WsseMiddleware(
            new SecurityProfile(),
            outbound: [
                new Outbound\Timestamp(),
                (new Outbound\Signature(new Signing\Symmetric($sessionKey)))
                    ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
                    ->withParts([Part::body(), Part::timestamp()]),
                (new Outbound\Encryption($sessionKey))
                    ->withParts([Part::body()]),
                // The endorsement: a certificate you control, over the signature above.
                (new Outbound\Signature(new Signing\Asymmetric($clientCertificate, KeyRef::Thumbprint)))
                    ->withParts([Part::primarySignature()]),
            ],
            inbound: [
                // The response is keyed by the same session key, resolved from the exchange, so there is no
                // private key to unwrap anything with and nothing to hand over.
                new Inbound\Decrypt(useEstablishedKey: true),
                new Inbound\VerifySignature(
                    $trustStore,
                    signed: [Part::body(), Part::timestamp()],
                    useEstablishedKey: true,
                ),
                new Inbound\ValidateTimestamp(),
            ],
        ),
    ])
);
```
