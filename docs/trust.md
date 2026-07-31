# Trust: what a verified signature proves

[← Back to the deep dives](../README.md#deep-dives)

Background for [`Inbound\VerifySignature`](inbound-blocks.md#inbound-verifysignature): what anchoring a
certificate does and does not buy you, and how to close the gap.

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
| The covering list's signature does not verify against an anchor | Rejected. A forged empty list would otherwise un-revoke everything |

That last rule is why the lists live on the trust store rather than beside it: a CRL is believed only once its
own signature verifies against one of the same anchors. Note the third row in particular: enabling revocation
and then forgetting a CRL for one of your issuers **rejects that issuer's signers** rather than skipping them,
because a configuration that reads as enabled while checking nothing is worse than one that is plainly off. For
the same reason, `withRevocationLists()` with no arguments is refused outright.

Every one of these rejections collapses into the same uniform `SecurityFault` as any other untrusted
certificate, so a peer cannot learn that it was revoked, or that your lists are stale or missing. The specific
reason is chained for your logs.

