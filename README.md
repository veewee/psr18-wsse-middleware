# SOAP WSSE/WSA Middleware

This package adds WSSE (WS-Security), and WSA (WS-Addressing) to your PSR-18 based SOAP transport.

From this major version on, the XML-Security layer lives inside this package. It signs, encrypts, decrypts and
verifies on the modern PHP DOM, so you no longer pull in `robrichards/wse-php` or `robrichards/xmlseclibs` at
runtime. The cryptography underneath is split: `phpseclib/phpseclib` performs the symmetric ciphers, the RSA and
ECDSA signatures and the RSA key transport, `ext-openssl` performs certificate path validation and key parsing,
and digests run on `ext-hash`. Because the timestamp parser uses the ICU date formatter, the requirements now
also include `ext-intl`.

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

Requires *at least* **PHP 8.4.21+**: signature canonicalization relies on a libxml fix that shipped in 8.4.21, and
`ext-intl` and `ext-openssl` must be enabled. Install `ext-gmp` or `ext-bcmath` for native-speed RSA/ECDSA math.

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
| [Inbound blocks](docs/inbound-blocks.md) | The same for `Decrypt`, `VerifySignature`, `ValidateTimestamp`, and what a `soap:Fault` reply gives you |
| [Choosing parts and key references](docs/parts-and-key-references.md) | `Part`, the dynamic parts, `KeyRef` and `EncKeyRef` |
| [Key stores](docs/key-stores.md) | Loading certificates, private keys, PEM bundles and `.p12` / `.pfx` files |
| [Trust](docs/trust.md) | Why a verified signature is not an authenticated peer, pinning, and opt-in revocation checking |
| [Security profile and defaults](docs/security-profile.md) | `SecurityProfile`, `CryptoPolicy`, the inbound allow-lists, and what is rejected by default and why |
| [The XML-Security layer](docs/xmlsecurity.md) | Swapping an engine service, and signing or encrypting plain XML without SOAP |
| [Importing a peer's existing configuration](docs/importing-a-peer-configuration.md) | Turning a SoapUI project or an IBM WebSphere descriptor you were handed into these blocks |

## The building blocks

Every block is a small, immutable value object you drop into the `outbound` or `inbound` list.

| Outbound | Adds |
|---|---|
| [`Timestamp`](docs/outbound-blocks.md#outbound-timestamp) | A `wsu:Timestamp` so the receiver can reject a stale or replayed call |
| [`Username`](docs/outbound-blocks.md#outbound-username) | A `wsse:UsernameToken`, with a plaintext or digested password |
| [`BinarySecurityToken`](docs/outbound-blocks.md#outbound-binarysecuritytoken) | Your X.509 certificate as a base64-DER token |
| [`Signature`](docs/outbound-blocks.md#outbound-signature) | A detached, multi-reference `ds:Signature` |
| [`Encryption`](docs/outbound-blocks.md#outbound-encryption) | XML-Enc ciphertext for the parts you name, under a fresh session key |
| [`SamlAssertion`](docs/outbound-blocks.md#outbound-samlassertion) | A SAML 1.1 / 2.0 assertion you obtained from an STS |

| Inbound | Checks |
|---|---|
| [`Decrypt`](docs/inbound-blocks.md#inbound-decrypt) | Decrypts the `xenc:EncryptedData` parts with your private key |
| [`VerifySignature`](docs/inbound-blocks.md#inbound-verifysignature) | The signature verifies, and the parts you require were covered by a trusted signer |
| [`ValidateTimestamp`](docs/inbound-blocks.md#inbound-validatetimestamp) | The response is not stale, future-dated, or past its own `Expires` |

### The order to list them in

Blocks run in the order you write them, and the order is part of your security policy. Nothing inspects the
list you compose, so these are yours to get right:

- **Outbound:** `Timestamp`, then the tokens (`Username`, `BinarySecurityToken`, `SamlAssertion`), then
  `Signature`, then `Encryption`. Signing before encrypting is what lets the receiver verify the signature over
  the plaintext it will read.
- **Inbound:** `Decrypt`, then `VerifySignature`, then `ValidateTimestamp`. Verifying before decrypting fails
  closed against an encrypt-then-sign peer, so that mistake breaks loudly rather than silently.
- **An empty `inbound` list checks nothing.** A client that signs every request and accepts any response at all
  is a valid configuration as far as this middleware is concerned. If you sign outbound, verify inbound.
- **`ValidateTimestamp` needs a signed timestamp.** `VerifySignature` requires the body by default but nothing
  more, so name `Part::timestamp()` too.

## Common flows

The following are complete, copy-pasteable setups. Adapt the file paths, credentials and parts to your service.

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

$clientCertificate = ClientCertificate::fromFile('client.pem')->withPassphrase('xxx');

// Step 1. Fetch an assertion from the STS by signing the request to it.
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
                new Outbound\Signature($clientCertificate, keyRef: Outbound\KeyReference\KeyRef::BinarySecurityToken),
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
                // ... Then encrypt:
                new Outbound\Encryption($recipient),
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
