# Trust: what a verified signature proves

[← Back to the deep dives](../README.md#deep-dives)

Background for [`Inbound\VerifySignature`](inbound-blocks.md#inbound-verifysignature): what anchoring a
certificate does and does not buy you, and how to close the gap.

## At a glance

Anchoring a CA proves a response was signed by somebody that CA vouched for, never that it was signed by your
service. Pick how you close that:

| Your situation | Do this | Cost |
|---|---|---|
| One endpoint, a stable certificate | Pin it: `TrustStore::fromCertificates($theirLeaf)` | You ship a new file when they rotate |
| Many endpoints, or short-lived certificates | Anchor the CA and add `->onTrustedSigner($check)` | You write the identity check |
| You need revocation as well | Anchor the CA and add `->withRevocationLists(...)` | You supply and refresh the CRLs |
| A CA you fully control, issuing only to you | Anchor it alone | Nothing, if that stays true |

**Pinning and revocation checking do not combine.** Revocation wants a list issued by the signer's own issuer,
and a pinned certificate is not its own issuer, so the check fails closed. Adding the CA to fix that re-trusts
everything that CA ever signed, which is what the pin existed to prevent. Pick one row, not two.

## Chain validity is not authentication

**If you anchor a CA, you are trusting every certificate that CA ever issued.** The check proves the response
was signed by *somebody the CA vouched for*, never that it was signed by *your service*. Where the anchor is a
public root, or a corporate CA that also issues certificates to other services or tenants, anyone holding one of
those certificates can sign a response your client accepts.

Two ways to close that, and you want at least one:

**Pin the service's own certificate.** Put it in the trust store instead of its issuer. It is matched directly,
so no chain has to be built:

```php
$trustStore = TrustStore::fromCertificates(Certificate::fromFile('service-leaf.pub'));
```

This is the strongest option and needs no extra code. Its cost is rotation: when the service replaces its
certificate you must ship the new one, so keep both in the store across a planned changeover.

**A pin does not combine with revocation checking.** Revocation looks for a list issued by the signer's own
issuer, and verifies that list against an anchor in the same store. A pinned certificate is not its own issuer,
so no supplied list covers it and the check fails closed. Adding the issuing CA to the store to fix that also
makes every certificate that CA ever signed trusted again, which is the exposure the pin existed to close. Pick
one: pin the peer, or anchor the CA and check revocation. A pin needs revocation less anyway, since you are
trusting exactly one certificate and withdrawing trust means removing it from your store.

**Or name the identity you expect.** When you have to anchor a CA (short-lived certificates, many endpoints),
check who signed. The callback runs only after the signature verified and the required parts were confirmed
covered, and throwing from it refuses the message as any other inbound failure:

```php
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\DistinguishedName;
use Soap\Psr18WsseMiddleware\KeyStore\TrustedSigner;

$expected = DistinguishedName::fromString('CN=payments.example.com,O=Example,C=BE');

(new Inbound\VerifySignature($trustStore, signed: [Part::body(), Part::timestamp()]))
    ->onTrustedSigner(function (TrustedSigner $signer) use ($expected): void {
        if (!$signer->subjectDistinguishedName()->equals($expected)) {
            throw new RuntimeException('the response was signed by an unexpected peer');
        }
    });
```

- `onTrustedSigner(callable(TrustedSigner): void $check): self` returns a copy with the check registered.
  `TrustedSigner` carries `subjectDistinguishedName()` and `certificate()`, so you can compare the subject, or
  the certificate's own bytes for a per-message pin.

A signature keyed by a symmetric secret names no signer: one key both produces and checks it, so there is no
identity for a check to run against. A message signed **only** that way, with a check registered, is
**refused** rather than accepted with the check quietly skipped. That is also how you require a message to
carry an endorsing signature: the check has a signer to run against only when a certificate signed too.

When a message carries several signatures, the check runs against **every** signer and all of them must pass.
All rather than any, because you are naming the identity you expected: a second signature from some other
certificate your trust store happens to hold is exactly the thing you did not expect. It costs a message a
lenient reading would have accepted, and it stops an identity you never named contributing to one you believe
you checked.

## Revocation checking (opt-in)

By default a signer that has been revoked but is still inside its validity window verifies. To check
revocation, add the CRLs to the trust store:

```php
use Soap\Psr18WsseMiddleware\KeyStore\CertificateRevocationList;

$trustStore = TrustStore::fromCertificates(Certificate::fromFile('service-ca.pub'))
    ->withRevocationLists(CertificateRevocationList::fromFile('service-ca.crl'));
```

The lists are yours to supply and refresh. **Nothing is fetched over the network**, so enabling this adds no I/O,
no timeout, and no new denial-of-service lever to the inbound path. Distribution-point and OCSP lookups are
deliberately not implemented.

Once enabled the check is **fail-closed in every direction**: a signer is accepted only when a list that is
trusted, current, and issued by that signer's own issuer says nothing about it:

| Situation | Outcome |
|---|---|
| The list is current and does not name the certificate | Accepted |
| The list names the certificate | Rejected |
| No supplied list was issued by the signer's issuer | Rejected. An unrelated CA's list says nothing about this signer |
| The covering list is past its `nextUpdate` | Rejected. A stalled refresh must not silently disable the check |
| The covering list states a `thisUpdate` in the future | Rejected. A list issued later than now is not evidence about now |
| The covering list's signature does not verify against an anchor | Rejected. A forged empty list would otherwise un-revoke everything |

Supply as many lists as you like: **every** current list issued by the signer's issuer is read, and the
certificate is rejected if any of them names it. That matters during a rollover, when the superseded list and
its replacement are both still inside their `nextUpdate` and only the newer one names the compromised serial;
consulting whichever happened to be passed first would let array order decide whether a revoked signer is
accepted. An expired list left in the store beside its replacement is ignored rather than fatal, but if no
current list covers the issuer, the staleness becomes the rejection.

Two limits are worth knowing before you rely on this:

- **Only the end-entity certificate is checked.** A revoked intermediate CA in the presented chain is not
  detected, because the check asks for a list issued by the leaf's own issuer. If you anchor a root and your
  peers chain through intermediates, revoking an intermediate will not stop messages signed under it.
- **The list must be signed by a configured anchor.** A CRL issued by an intermediate that is itself only
  peer-supplied cannot be believed, so in a root-plus-intermediate PKI you need the intermediate anchored in
  the trust store for its CRLs to be usable.

That last rule is why the lists live on the trust store rather than beside it: a CRL is believed only once its
own signature verifies against one of the same anchors. Note the third row in particular: enabling revocation
and then forgetting a CRL for one of your issuers **rejects that issuer's signers** rather than skipping them,
because a configuration that reads as enabled while checking nothing is worse than one that is plainly off. For
the same reason, `withRevocationLists()` with no arguments is refused outright.

Every one of these rejections collapses into the same uniform `SecurityFault` as any other untrusted
certificate, so a peer cannot learn that it was revoked, or that your lists are stale or missing. The specific
reason is chained for your logs.

