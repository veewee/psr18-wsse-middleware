# Key stores

[← Back to the deep dives](../README.md#deep-dives)

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
- `->publicCertificate()` returns the end-entity certificate wherever the file lists it. A combined file that
  puts its CA ahead of your own certificate is read correctly: the end-entity is derived from issuer linkage,
  not from position.

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
  throws if the bundle embeds no chain. It treats entry 0 as the leaf certificate and skips it, which is correct
  for an identity bundle. A truststore is a different shape, so load it as a PEM bundle instead (below).
- A wrong passphrase or a file that is not a PKCS#12 throws a `Pkcs12Exception` with a generic message.

## Trust anchors from a PEM bundle

A trusted-CA file holds one or more certificates concatenated into a single PEM file, and no private key. Load
it as a `Pem` bundle and hand it to the trust store, where **every** certificate becomes a trust anchor. There
is no leaf to skip here, so a file of thirty anchors gives you thirty.

```php
use Soap\Psr18WsseMiddleware\KeyStore\Pem;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;

$trustStore = TrustStore::fromPem(Pem::fromFile('anchors.pem'));
```

- `Pem::fromFile(string $file): Pem` reads the file from disk, `Pem::fromString(string $contents): Pem` from
  raw bytes, and `->certificates(): list<Certificate>` returns the individual certificates.
- Anything outside the armor is ignored, so the `Bag Attributes`, `subject=` and `issuer=` lines
  `openssl pkcs12 -nokeys` writes ahead of each certificate need no cleaning up first.
- A file with no certificate in it throws an `InvalidPemBundle`, and so does a file whose last certificate or
  private key is cut off: a truncated file is refused rather than loaded as the anchors that happened to survive.
  A certificate block with another PEM block nested inside it is refused for the same reason.
- `Pem::certificatesIn(string $contents): list<Certificate>` reads the certificates on their own, without
  looking at any key material alongside them. Use it when the certificates are all you want, so a problem with
  the key cannot surface as a failure to read a certificate.
- `TrustStore::fromPem()` throws an `InvalidTrustStore` when the bundle carries no certificate, because a store
  with zero anchors accepts nothing.

### A PEM file that also carries a private key

PEM is only a container, so a file may hold a private key next to its certificates. `Pem` reads such a file and
hands the key back through `->privateKey(): ?Key`, which is `null` when the file held certificates alone.

Deciding whether a key belongs in the file is the caller's job, not the reader's:

- `TrustStore::fromPem()` refuses it. A trust store holds public certificates only, so a key there means the
  wrong file was exported — usually a client bundle where a trusted-CA file was meant.
- `ClientCertificate` is the class for a certificate and its private key in one file, and `Key` for a private
  key on its own.

```php
$pem = Pem::fromFile('client.pem');

$pem->certificates();   // list<Certificate>
$pem->privateKey();     // ?Key, and ->withPassphrase('xxx') on it if the key is encrypted

TrustStore::fromPem($pem);   // throws InvalidTrustStore: this file carries key material
```

A file carrying two private keys is refused outright: nothing states which identity is yours, and taking the
first would let the file's layout decide what your messages get signed with.

## Converting a Java keystore

A `.jks` or `.jceks` file is a Java keystore, and this package does not read one: it takes PEM and PKCS#12.
Nothing in PHP reads them either, so there is no option to install: neither `ext-openssl` nor `phpseclib`
supports the format. Convert the file with `keytool`, which ships with Java.

Which commands you need depends on what the file holds, and getting that wrong is the usual cause of a missing
anchor. `keytool -list` tells you: `PrivateKeyEntry` lines are a signing identity, `trustedCertEntry` lines are
trust anchors.

Every export needs the keystore password. Keep it out of your shell history and out of any log by putting it in
an environment variable rather than on the command line:

```bash
read -rs KEYSTORE_PASSWORD && export KEYSTORE_PASSWORD
keytool -list -keystore theirs.jks -storepass "$KEYSTORE_PASSWORD"
```

**A keystore holding a signing identity** (a certificate with its private key) converts in one command and loads
as a PKCS#12:

```bash
keytool -importkeystore -srckeystore theirs.jks -srcstoretype JKS \
        -destkeystore theirs.p12 -deststoretype PKCS12 \
        -srcstorepass "$KEYSTORE_PASSWORD" -deststorepass "$KEYSTORE_PASSWORD"
```

```php
$clientCertificate = ClientCertificate::fromPkcs12(Pkcs12Bundle::fromFile('theirs.p12', $passphrase));
```

**A truststore holding trust anchors** (certificates, no private key) needs a second command. The converted
PKCS#12 carries no private key, so `Pkcs12Bundle` will not load it; extract the certificates to a PEM bundle
instead:

```bash
keytool -importkeystore -srckeystore truststore.jks -srcstoretype JKS \
        -destkeystore truststore.p12 -deststoretype PKCS12 \
        -srcstorepass "$KEYSTORE_PASSWORD" -deststorepass "$KEYSTORE_PASSWORD"
openssl pkcs12 -in truststore.p12 -nokeys -passin env:KEYSTORE_PASSWORD -out anchors.pem
```

```php
$trustStore = TrustStore::fromPem(Pem::fromFile('anchors.pem'));
```

Use `TrustStore::fromPem()` here, not `TrustStore::fromPkcs12()`. Every entry in a truststore is an anchor, while
`fromPkcs12()` is built for an identity bundle and skips the first certificate as the leaf, which on a truststore
silently costs you one anchor. Check the anchor count against the `trustedCertEntry` count `keytool -list`
reported.

