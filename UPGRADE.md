# Upgrade guide

## Upgrading to the new major version

This release swaps the old `robrichards/wse-php` wrapper for a WSSE engine that lives in this package. You
still build security as a list of blocks, so the idea is familiar, but the names and some of the moving
parts changed. Here is what to check when you upgrade.

### The engine is now part of this package

Signing, encryption, decryption and verification run on `ext-openssl` and the modern PHP DOM. You no longer
need `robrichards/wse-php` or `xmlseclibs` at runtime, and the old encryption-bug patch (the
`cweagans/composer-patches` workaround for `wse-php`) is no longer needed. You can drop that patch and the
dev dependency from your project.

### Two block lists instead of one

The constructor arguments were renamed to say what they do:

- `outgoing:` is now `outbound:`, the blocks that secure the request you send.
- `incoming:` is now `inbound:`, the blocks that check the response you get back.

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

### Key references replaced the KeyIdentifier classes

The `WSSecurity\KeyIdentifier\*` classes are gone. You now pick a reference style with a small value object.
For signatures, use `KeyRef::binarySecurityToken()`, `KeyRef::subjectKeyIdentifier()`,
`KeyRef::issuerSerial()` or `KeyRef::thumbprint()`. For encryption, `EncKeyRef` offers the same set.

### Algorithm enums moved

The algorithm enums (`SignatureMethod`, `DigestMethod`, `SignatureCanonicalization`, `DataEncryptionMethod`
and `KeyEncryptionMethod`) moved from the `WSSecurity\` root into `WSSecurity\Algorithm\`. Update your `use`
statements. The defaults are secure on their own, so in most cases you can stop passing these explicitly.

### One WS-Addressing middleware

`WsaMiddleware2005` is gone. There is now a single `WsaMiddleware` that takes the addressing version as an
argument, and its default namespace is the W3C 2005/08 one. If you relied on the older 2004/08 default, pass
the version you need explicitly.

### A couple of smaller changes

- The `withActor()` and `withMustUnderstand()` helpers on the middleware were removed. The blocks now create the security header with safe defaults.
- A response that fails an inbound check throws a single, uniform security error. It does not reveal which step failed, so the middleware cannot be used as an oracle.
