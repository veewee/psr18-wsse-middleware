# Inbound blocks

[← Back to the deep dives](../README.md#deep-dives)

The blocks that check the response you get back. Every block is a small, immutable value object you drop
into the `inbound` list: a short example, then every constructor argument and fluent method with its
default and what it expects.

See [Outbound blocks](outbound-blocks.md) for their request-side counterparts, and the
[README](../README.md#the-building-blocks) for the order to list them in.

## Inbound: `ResolveOptimizedBytes`

Puts back the bytes a peer moved out of the document. Place it **first** in the inbound list, ahead of
`Decrypt` and `VerifySignature`, both of which read values it restores.

```php
use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\AttachmentParts;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartCoverage;

$inbound = [
    new Inbound\ResolveOptimizedBytes(
        AttachmentParts::response($attachmentStorage, ExternalPartCoverage::Content),
    ),
    new Inbound\Decrypt($privateKey),
    new Inbound\VerifySignature($trustStore, signed: [Part::body()]),
];
```

A peer with MTOM enabled writes an `xop:Include` where a security value belongs and carries the raw bytes in
a MIME part beside the envelope, skipping the 33% base64 costs. **Nothing negotiates this.** Apache CXF turns
it on by default whenever MTOM is on, and .NET and Metro do it to any large encrypted content
unconditionally, so the shape arrives without either side having chosen it. Without this block such a message
is refused as a cipher value that will not decode.

Three values are restored and no others: the `xenc:CipherValue` of an `xenc:EncryptedData` or an
`xenc:EncryptedKey`, and a `wsse:BinarySecurityToken`. Those are the three a peer optimizes. An
`xop:Include` anywhere else is ordinary MTOM content belonging to the attachments middleware, and is left
exactly as it is.

- `__construct(ExternalParts $carriers)`: where the bytes are. Pass `AttachmentParts::response(...)` for the
  inbound side. Required, because a reference is resolved against these parts or refused: nothing is fetched,
  whatever scheme the reference names.

Registering the block does **not** require the shape to be present. The peers switch on a size threshold, so
one message carries an optimized `xenc:EncryptedData` beside an inline `xenc:EncryptedKey`, and the next
carries neither. Every value is decided on its own.

Refused, as one uniform `SecurityFault` like everything else inbound: a reference naming no supplied part, a
value that describes its content two ways at once (text beside a pointer, two pointers, one nested below a
child, or one naming nothing), and a message declaring more than 32 optimized values. A part that reads
nothing is left to the length check that already refuses it.

The consumed `application/ciphervalue` parts stay in your attachment collection. Restoring a value does not
consume the part it came from, and dropping it would need a capability the `ExternalParts` seam does not have.
Only code that deliberately registered this block ever sees them.

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

- `?Key $privateKey = null`: your recipient private key as a `KeyStore\Key`, which unwraps an
  `xenc:EncryptedKey` a peer wrapped for you.
- `?PreSharedSessionKey $preSharedKey = null`: a secret both sides already hold. A wrapped or derived key is
  never passed here: it was established while the request was written and the exchange already holds it, and
  neither could be handed to an inbound block anyway, because both *mint* and would write a token into the
  response.
- `bool $useEstablishedKey = false`: read the key this exchange established for itself. A correlated response
  carries no key of its own: each element names the key its own request conveyed, and this says such a response
  is what you expect. Nothing is handed over, because the request registered the key while it was written.
  **Off by default, and off means off**: a block given only a trust store refuses a MAC keyed by an established
  key rather than accepting one it was never configured for, so a deployment that wants certificates only gets
  certificates only. A pre-shared secret turns the same reading on by itself, since it is registered into the
  same place.

Same shape as `VerifySignature`, for the same reason: both blocks answer "what key material do I hold?".
At least one of the three must be given:

```php
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound;

new Inbound\Decrypt($privateKey);                          // a key wrapped under our certificate
new Inbound\Decrypt(preSharedKey: $secret);                // a secret both sides hold
new Inbound\Decrypt(useEstablishedKey: true);              // our own request conveyed the key
```
- `withAttachments(ExternalParts $attachments): self`: also decrypt the response's encrypted attachments. Off
  by default. Pass `AttachmentParts::response($attachmentStorage, ExternalPartCoverage::Complete)`; see
  [Attachment security](attachments.md).
  ```php
  use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\AttachmentParts;
  use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartCoverage;

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
  part gets the media type the sender recorded before encrypting. Registering parts is equally the requirement
  that they arrive encrypted, and `AttachmentParts` registers every attachment in the response, so one that
  travelled in the clear beside encrypted ones refuses the message rather than being left alone.

The wrapped session key is read from the `wsse:Security` header addressed to you. The header the profile's
`actorOrRole` selects, the same one the signature verifier reads. A response carrying no header for you is
refused rather than decrypted against an `xenc:EncryptedKey` found elsewhere in the envelope: your certificate is
public, so anyone can wrap a key to you, and nothing about a key's position makes it yours.

### A response keyed by the exchange's own secret

A response to a request that established a symmetric key carries no `xenc:EncryptedKey` at all: the key
travelled with the request, so each `xenc:EncryptedData` only points back at it. Which of the two shapes a
given message uses is decided by the message: a container carrying a wrapped key has that key unwrapped, and a
container carrying none has each part's key resolved from what the exchange established. That the second shape
may arrive at all is yours to state, with `useEstablishedKey: true`, and a block that did not state it refuses
one rather than opening it. Both may be stated at once for a peer that uses either.

Both ways a peer may name a session key are read: a `wsse:KeyIdentifier` carrying the `EncryptedKeySHA1`
digest, and a `wsse:Reference` whose URI carries that same digest and whose `ValueType` declares it. This
package emits the first; WSS4J's derived-key path emits the second. A `wsc:DerivedKeyToken` is read whether or
not it declares an `Algorithm`, since the attribute is optional and P_SHA1 is the default, and whether or not it
carries a `Label`.

**Established, and nothing else.** A reference naming a key this exchange never saw is refused; there is no
fallback and no second candidate. The keys of one exchange are scoped to that exchange and shared only between
its request and its response, because a wider cache would let a response be opened with a key from a different
exchange, which is replay.

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

new Inbound\VerifySignature($trustStore,
    signed: [Part::body(), Part::timestamp()],
);
```

- `?TrustStore $trustStore = null`: the certificates you trust as signers. Build it with
  `TrustStore::fromCertificates(...)`. Required, and still required for a purely symmetric deployment: the block
  cannot know in advance which kind of signature will arrive, and one keyed by a certificate must still be
  checked against something. Pass a store holding the anchors you would accept.
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
  `null` for a deployment that receives no certificate-keyed signature at all. A trust store handed over and
  never read would say this block accepts something it does not.
- `?PreSharedSessionKey $preSharedKey = null`: the secret a MAC is verified against, when both sides hold the
  key. Only a pre-shared key is passed here: a wrapped or derived key was established while the request was
  written and the exchange already holds it, and neither could be handed to an inbound block anyway, because
  both *mint* and would write a token into the response.
- `bool $useEstablishedKey = false`: read the key this exchange established for itself. A correlated response
  carries no key of its own: each element names the key its own request conveyed, and this says such a response
  is what you expect. Nothing is handed over, because the request registered the key while it was written.
  **Off by default, and off means off**: a block given only a trust store refuses a MAC keyed by an established
  key rather than accepting one it was never configured for, so a deployment that wants certificates only gets
  certificates only. A pre-shared secret turns the same reading on by itself, since it is registered into the
  same place.

All three are optional and **at least one must be given**:

```php
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound;

new Inbound\VerifySignature($trustStore, signed: [Part::body()]);                 // certificates
new Inbound\VerifySignature(preSharedKey: $secret, signed: [Part::body()]);       // a shared secret
new Inbound\VerifySignature($trustStore, $secret, signed: [Part::body()]);        // both, one pass
new Inbound\VerifySignature(useEstablishedKey: true, signed: [Part::body()]);     // our request's own key

// A response that may carry either: a certificate signature, or a MAC keyed by our request's own key.
new Inbound\VerifySignature($trustStore, signed: [Part::body()], useEstablishedKey: true);
```

**Both at once is not unusual here**, unlike on `Decrypt`: one message may carry a MAC over the body and a
certificate signature endorsing it, which is the shape [the outbound side
emits](outbound-blocks.md#endorsing-a-signature-with-a-certificate-you-control). Each signature is resolved by
its own `ds:KeyInfo`, so one block verifies them all in a single pass and two blocks would be wrong rather than
merely redundant.

A response may carry more than one `ds:Signature` directly inside the header addressed to you, and **every one
of them must verify**. That is what lets a peer endorse its own response signature the way
[the outbound side can](outbound-blocks.md#endorsing-a-signature-with-a-certificate-you-control), and it is also
what makes an injected signature refuse the message: a second one is one more thing that must hold, never an
alternative the verifier may pick. What you may require is the union of what they covered. Signatures nested
deeper than a direct child are still not candidates at all, which is the wrapping defense and does not depend on
how many there are. The count is bounded, because each signature costs a canonicalization, a digest per
reference and a crypto operation.

**Every signature that contributes coverage must be by the same party.** Where you anchor trust on a CA rather
than pinning the peer, anyone holding a certificate that CA issued can produce a signature this block accepts,
so without this rule they could append their own token and a signature over it to a message your peer signed: a
`Part::securityHeaderContents()` requirement would then be satisfied partly by each, and nothing in the result
would tell you. A message genuinely signed by two contributing identities is refused rather than merged, because
which parts each of them vouched for is a question this reports no answer to.

A reference to a `ds:Signature` resolves by the native `Id` that XML Signature declares on it as well as by
`wsu:Id`, because that is how a peer names the signature its endorsement covers. Everywhere else only `wsu:Id`
is read.

A party is a certificate, or the holder of a secret this exchange established. **Counting the secret is what
makes the rule reach the shape it matters most in.** A MAC names no certificate, so a rule stated over signers
alone would see a single signer in a response where the peer MACed the body and somebody else signed the
timestamp, and the union would quietly span the two.

An endorsement is the exception: an endorsing token belongs to the sender and legitimately differs from the
party whose signature it endorses. A signature counts as an endorsement when it covers a `ds:Signature` that
itself verified, which is the same test CXF applies to an endorsing supporting token.

**An endorsement's own coverage is not reported, and that is what keeps the exception honest.** Only the
signatures it endorsed enter what you may require. A peer covers more alongside the primary signature as a
matter of course, so recognising an endorsement cannot mean requiring it to cover nothing else: under
`sp:ProtectTokens` a CXF endorsement also covers its own token, and a supporting token may declare signed parts
of its own. Discarding the rest is what stops the exception being a way in: a signature covering the primary
plus a part of its own choosing is an endorsement whose choice of part is thrown away, so there is nothing to
launder. The consequence to know is that a `Part::securityHeaderContents()` requirement is not satisfied by an
endorsing token's own element, because only the endorsing party ever vouched for it.

Worth knowing how this compares to your peers, because it is stricter than both. WSS4J pools every verified
signature's references and answers "was this element signed" from the pool, and Apache CXF validates
`sp:SignedParts` against the same flattened set; neither consults which credential covered what. So a message
this block refuses may well be one a WSS4J or CXF receiver accepts.
- `withAttachments(ExternalParts $attachments): self`: require the response's attachments to be covered by the
  verified signature. Off by default. Pass `AttachmentParts::response($attachmentStorage, ExternalPartCoverage::Complete)`; see
  [Attachment security](attachments.md).
  ```php
  use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\AttachmentParts;
  use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartCoverage;

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

**A token covered through its reference verifies.** A peer may cover its signing token by pointing a
`ds:Reference` at the `wsse:SecurityTokenReference` that names it, with the WS-Security `#STR-Transform`
telling the verifier to substitute the token before digesting. WSS4J and CXF emit this routinely, and it is
accepted here with no configuration: the transform's own canonicalization still goes through the profile's
`acceptedCanonicalizations` allow-list, so an inclusive method named inside it is refused by default like any
other. What the verifier reports as signed is the **token**, not the reference that named it, which is what
makes `Part::securityHeaderContents()` mean what you would expect.

Two of the reference forms are dereferenced: a `wsse:Reference` to a token by id, and a `wsse:KeyIdentifier`
naming a SAML assertion. Both name an element the message actually carries. A reference that instead names a
certificate: a `wsse:KeyIdentifier` holding a Subject Key Identifier or a thumbprint, or a
`ds:X509IssuerSerial`, is **refused**. A signer using one of those digested a `wsse:BinarySecurityToken` it
built from its own keystore, an element that never travelled, and reproducing that byte-for-byte from a
certificate found locally is guesswork. A digest over an approximation of what the signer digested proves
nothing, so this fails closed rather than nearly verifying. If you meet such a peer, the fix is for it to
reference its token directly.

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

**The same rule applies on the way in.** A signature over an element holding an `xop:Include` is refused
unless that same signature also carries a `ds:Reference` digesting the bytes the pointer names. Registering
the attachment here is what makes such a reference checkable, but registration alone is not enough: a part
being available says it arrived, not that anything vouches for it. A default WSS4J receiver does not expand
such an element before verifying, so a signature covering only the pointer verifies there while the file it
stands for travels unprotected. Refusing is deliberate: matching that peer would mean reproducing the
weakness.

- No required arguments. The freshness window (clock skew and maximum age) comes from the `SecurityProfile` on
  the context: `clockSkew()` and `timestampTtl()`. Configure the window on the profile, not on this block.

Dates are parsed strictly: only the exact instant formats a conforming peer emits are accepted. Every failure
collapses to one uniform `SecurityFault`.

## When the response is a SOAP fault

The inbound list runs on **every** response, a fault included. A service that answers with an unsigned,
unencrypted `soap:Fault` therefore fails whatever you registered (`VerifySignature` finds no signature,
`ValidateTimestamp` finds no timestamp) and you get the same uniform `SecurityFault` as any other refusal.
That is deliberate: skipping the checks for a fault-shaped body would let anyone who can inject a response
bypass every one of them by wrapping the payload in a fault.

What it should not cost you is the diagnosis. So when the failing response *is* a fault, the reason the peer
gave is chained into the refusal as a `PeerReportedFault`:

```php
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\PeerReportedFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;

try {
    $result = $client->call('...');
} catch (SecurityFault $fault) {
    $reported = $fault->getPrevious();
    if ($reported instanceof PeerReportedFault) {
        // "The peer returned a SOAP fault [soap:Sender]: Invalid security token"
        $logger->error($reported->getMessage(), ['exception' => $fault]);
    }
}
```

Both SOAP versions are read: `faultcode`/`faultstring` in 1.1, `Code/Value` and `Reason/Text` in 1.2. The
original cause stays reachable behind the `PeerReportedFault`, so nothing you had before is lost.

**This only fires when a check fails.** A fault reply that passes your inbound list is handed on untouched, and
`php-soap/encoding` raises its own `SoapFaultException` for it further up, carrying the fault in full including
the `detail` element. So the rule is: a fault you can act on programmatically arrives as `SoapFaultException`,
and a fault that arrived alongside a security failure arrives as a log line inside `SecurityFault`. The wording
of the two messages is deliberately identical, so one search of your logs finds either.

Three things this deliberately does not do. `SecurityFault`'s own message never changes, so the no-oracle
guarantee is untouched and nothing about which check failed leaks. The fault text is peer-supplied and
**unverified**, since nobody signed it, so it belongs in your log and nowhere near a decision your code makes;
it is stripped of control characters and capped in length for exactly that reason. And a fault is still a
refusal: no response, no configuration to change that.
