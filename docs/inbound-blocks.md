# Inbound blocks

[← Back to the deep dives](../README.md#deep-dives)

The blocks that check the response you get back. Every block is a small, immutable value object you drop
into the `inbound` list: a short example, then every constructor argument and fluent method with its
default and what it expects.

See [Outbound blocks](outbound-blocks.md) for their request-side counterparts, and the
[README](../README.md#the-building-blocks) for the order to list them in.

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

- `Key $privateKey`: your recipient private key as a `KeyStore\Key`. Required.
- `withAttachments(ExternalParts $attachments): self`: also decrypt the response's encrypted attachments. Off
  by default. Pass `AttachmentParts::response($attachmentStorage, ExternalPartCoverage::Complete)`; see
  [Attachment security](attachments.md).
  ```php
  use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\AttachmentParts;

  (new Inbound\Decrypt($privateKey))
      ->withAttachments(AttachmentParts::response($attachmentStorage, ExternalPartCoverage::Complete));
  ```
  The second argument says which coverage the peer's ciphertext must declare, and it is a requirement rather
  than a hint: a `Complete` adapter refuses a content-only `@Type` and the other way round. A
  default-configured CXF sender encrypts `Complete`, so that is usually the one to pass. See
  [Attachment security](attachments.md#how-much-of-a-part-a-protection-covers).
  Register these whenever the peer may encrypt an attachment. Unlike the in-document parts, an encrypted
  attachment is **not** quietly left alone when none are registered: a message naming one is refused, because
  otherwise it would read as fully decrypted while your code holds a file that is still ciphertext. Each opened
  part gets the media type the sender recorded before encrypting. A part that arrived unencrypted is untouched.

The wrapped session key is read from the `wsse:Security` header addressed to you. The header the profile's
`actorOrRole` selects, the same one the signature verifier reads. A response carrying no header for you is
refused rather than decrypted against an `xenc:EncryptedKey` found elsewhere in the envelope: your certificate is
public, so anyone can wrap a key to you, and nothing about a key's position makes it yours.

Any decryption failure collapses to one uniform `SecurityFault` that does not reveal which step failed. That
hides *which* step failed, not *whether* it did: a caller who can trigger requests still sees the difference
between a returned response and a thrown one. If you accept AES-CBC, read the note on
`acceptedDataEncryptionMethods` below.

**This block does not require anything to have arrived encrypted.** It decrypts what the response marks as
encrypted; it has no counterpart to `VerifySignature`'s `signed:` list. A peer, or a gateway in front of it,
that stops encrypting the sensitive region sends plaintext and nothing objects. If that matters to you, check
the region is present and shaped as you expect in your own application code after the exchange.

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

- `TrustStore $trustStore`: the certificates you trust as signers. Build it with
  `TrustStore::fromCertificates(...)`. Required.
- `signed: ?list<Part> $signed = null`: the parts that **must** be covered by a trusted signature. Pass it as a
  named argument (`signed:`). `null`, the default, requires `Part::body()`: without that floor, a peer holding
  any trusted certificate could sign one decoy element it minted in its own Security header and leave the body
  attacker-controlled. An explicit list replaces the default entirely, so name every part you depend on. Add
  `Part::timestamp()` whenever the peer signs one, which is what makes `ValidateTimestamp` mean anything. The
  default stops at the body on purpose: peers commonly leave their own `BinarySecurityToken` unsigned, so
  requiring the whole header contents would refuse conformant messages. The dynamic parts work here too:
  `Part::securityHeaderContents()` requires every token in the Security header to have been signed, and
  `Part::soapHeaders()` requires every other SOAP header block to have been signed.

  **An empty list is not the default.** `signed: []` replaces the body floor with no requirement at all, so any
  message carrying a signature from any trusted certificate passes, whatever that signature actually covers.
  Pass `null` (or omit the argument) if you want the default; pass a list only when you mean every part in it.
- `withAttachments(ExternalParts $attachments): self`: require the response's attachments to be covered by the
  verified signature. Off by default. Pass `AttachmentParts::response($attachmentStorage, ExternalPartCoverage::Complete)`; see
  [Attachment security](attachments.md).
  ```php
  use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\AttachmentParts;

  (new Inbound\VerifySignature($trustStore, signed: [Part::body()]))
      ->withAttachments(AttachmentParts::response($attachmentStorage, ExternalPartCoverage::Complete));
  ```
  The second argument says which coverage each reference must declare, and it is a requirement rather than a
  hint: a `Complete` adapter refuses a reference declaring the content transform. See
  [Attachment security](attachments.md#how-much-of-a-part-a-protection-covers).
  **Registering parts is the requirement that they be signed.** Every attachment present must be covered, so a
  peer that simply omits an attachment reference is refused rather than silently accepted: "the signature said
  nothing about this file" and "the file is signed" must not look the same to your code. Put this after
  `Inbound\Decrypt` when the attachments arrive encrypted, so the digest is checked against the plaintext the
  far side signed.

The accepted signature, digest and canonicalization algorithms come from the profile's allow-lists. By default
the signature allow-list covers RSA and ECDSA at SHA-256/384/512, and only the exclusive C14N variants are
accepted; to accept an inclusive variant, add it to the profile's `acceptedCanonicalizations` (see
[Security profile and defaults](security-profile.md)). Every failure cause collapses to one uniform
`SecurityFault` carrying no step-identifying detail, so the block is never a forgery oracle.

The signer's certificate must be trusted by the store, be within its validity window, and: if it carries a
`keyUsage` extension: assert either `digitalSignature` or `nonRepudiation` (`contentCommitment`). A
certificate with no `keyUsage` extension is not refused on that ground. No Extended Key Usage is required: the
X.509 Token Profile mandates none, and no registered EKU describes WS-Security message signing.

**A trusted certificate is not your peer.** If you anchor a CA here, every certificate that CA ever issued
verifies. Read [Trust: what a verified signature proves](trust.md) for what to do about that, and for
opt-in [revocation checking](trust.md#revocation-checking-opt-in).

## Inbound: `ValidateTimestamp`

Rejects a stale or future-dated response before your application sees it. It locates the single `wsu:Timestamp`
in the Security header and asserts the message is not expired, not older than the maximum age, and not stamped
in the future, each within the configured clock skew.

Both `wsu:Created` and `wsu:Expires` are required. The OASIS utility schema makes each optional, so a peer that
stamps only `wsu:Created` and leaves the receiver's own `timestampTtl` to bound the window is spec-legal and
will be refused here. That is deliberate, because a timestamp with no stated expiry gives the block nothing to
assert against, but it is a real interop refusal: if you meet such a peer, the fix is on their side or the block
comes out of your inbound list.

This is not replay detection. There is no nonce cache, so a captured response replayed inside the freshness
window is accepted; what the block does is bound how long that window stays open. Narrow `timestampTtl` and
`clockSkew` to shrink it.

**Pair it with a signed timestamp.** This block reads `wsu:Created` and `wsu:Expires` as text and cannot tell
whether anyone vouched for them. Unless `Part::timestamp()` is in `VerifySignature`'s `signed:` list, a peer
rewrites both values and the window is unbounded, which makes this block decorative. Register the two together:

```php
inbound: [
    new Inbound\VerifySignature($trustStore, signed: [Part::body(), Part::timestamp()]),
    new Inbound\ValidateTimestamp(),
],
```

```php
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound;

new Inbound\ValidateTimestamp();
```

- No required arguments. The freshness window (clock skew and maximum age) comes from the `SecurityProfile` on
  the context: `clockSkew()` and `timestampTtl()`. Configure the window on the profile, not on this block.

Dates are parsed strictly: only the exact instant formats a conforming peer emits are accepted. Every failure
collapses to one uniform `SecurityFault`.

