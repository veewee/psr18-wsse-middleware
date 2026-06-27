# SOAP WSSE/WSA Middleware

This package adds WSSE (WS-Security) and WSA (WS-Addressing) to your PSR-18 based SOAP transport.

From this major version on, the security engine lives inside this package. It signs, encrypts, decrypts and
verifies on top of `ext-openssl` and the modern PHP DOM, so you no longer pull in `robrichards/wse-php` or
`xmlseclibs` at runtime.

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

# How it works

You secure a message by composing building blocks. There are two lists.

The **outbound** list runs on the request you send: it can add a timestamp, sign the body, encrypt a part,
and so on. The **inbound** list runs on the response you get back: it can decrypt it, verify its signature
and check its timestamp.

Each block configures itself and comes with secure defaults, so you only spell out what your server asks
for. The shape follows the [WS-Security panel in SoapUI](https://www.soapui.org/docs/soapui-projects/ws-security/):
if you have a working SoapUI setup, you can rebuild it here one block at a time.

Presence is behaviour. Add a block and that protection is applied. Leave it out and it isn't. The order of
the list is the order things happen in.

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
                // ... sign, encrypt, add tokens
            ],
            inbound: [
                // ... decrypt, verify, validate the timestamp
            ],
        ),
    ])
);
```

## The blocks

Outbound, for securing the request:

- `Outbound\Timestamp`: stamps the message with a created/expires window so the receiver can reject stale or replayed calls.
- `Outbound\Username`: adds a username, and optionally a password (plaintext or digested).
- `Outbound\BinarySecurityToken`: attaches your X.509 certificate so the receiver can find the key that signed the message.
- `Outbound\Signature`: signs the parts you choose. By default that is the body and the timestamp.
- `Outbound\Encryption`: encrypts sensitive parts for the recipient.
- `Outbound\SamlAssertion`: carries a SAML assertion you obtained from an STS.

Inbound, for checking the response:

- `Inbound\Decrypt`: decrypts the encrypted parts of the response with your private key.
- `Inbound\VerifySignature`: verifies the signature and confirms that the parts you require were signed by a trusted certificate.
- `Inbound\ValidateTimestamp`: checks the response is fresh, within a clock skew you can configure.

The signing, encryption, decryption and verification blocks are driven by the package's WSSE engine. Today
those heavier blocks take the engine's services in their constructor; a simpler way to assemble them is
planned. Until then, the tests under `tests/Unit/WSSecurity` are the most reliable reference for wiring a
full signing or encryption flow.

## WsaMiddleware

If your server expects WS-Addressing headers, add the WSA middleware. It is one configurable middleware that
covers both addressing versions, and it defaults to the W3C 2005/08 namespace.

```php
use Http\Client\Common\PluginClient;
use Soap\Psr18Transport\Psr18Transport;
use Soap\Psr18WsseMiddleware\WsaMiddleware;
use Soap\Psr18WsseMiddleware\Wsa\WsaNamespace;

$transport = Psr18Transport::createForClient(
    new PluginClient($yourPsr18Client, [
        new WsaMiddleware(),
        // or pick the addressing version explicitly:
        new WsaMiddleware(WsaNamespace::W3c200508),
    ])
);
```

## Adding a username and password

Some services just want a username and password:

```php
use Soap\Psr18WsseMiddleware\WsseMiddleware;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

$wsseMiddleware = new WsseMiddleware(
    new SecurityProfile(),
    outbound: [
        new Outbound\Username('your-user', 'your-password'),
    ],
);
```

## Key stores

The package wraps your keys and certificates in small value objects:

- `KeyStore\Certificate`: a public X.509 certificate in PEM format.
- `KeyStore\Key`: a PKCS#8 private key in PEM format.
- `KeyStore\ClientCertificate`: a certificate and a private key together in one PEM bundle.

```php
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Key;

$privateKey = Key::fromFile('security_token.priv')->withPassphrase('xxx');
$certificate = Certificate::fromFile('security_token.pub');

// or load both from a single bundle:
$bundle = ClientCertificate::fromFile('client-certificate.pem')->withPassphrase('xxx');
$privateKey = $bundle->privateKey();
$certificate = $bundle->publicCertificate();
```

Starting from a `.p12` file? Convert it to a private key and a public certificate first:

```bash
openssl pkcs12 -in your.p12 -out security_token.pub -clcerts -nokeys
openssl pkcs12 -in your.p12 -out security_token.priv -nocerts -nodes
```

## Choosing what to sign and how to reference your key

A few value objects let you say which parts to protect and how a token is referenced, without touching the
engine:

- `Part::body()`, `Part::timestamp()`, `Part::element($namespace, $localName)` and `Part::byId($id)` name the parts a block targets.
- `KeyRef` and `EncKeyRef` choose how your certificate is referenced in a signature or encryption: a binary token, a subject key identifier, an issuer and serial, or a thumbprint.
- `Trust\TrustStore::fromCertificates(...)` lists the certificates you trust when verifying a response.

## Settings and secure defaults

You configure a `SecurityProfile` once on the `WsseMiddleware` and it reaches every block through the
per-message context. Each block lets you override only what you need: it looks at the per-block setting
first, then the profile on the context. The defaults reject weak algorithms such as SHA-1 and 3DES, and use
SHA-256 with exclusive canonicalization.
