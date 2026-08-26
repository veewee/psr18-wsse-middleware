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
