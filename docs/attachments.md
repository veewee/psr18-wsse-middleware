# Attachment security

Signing, verifying, encrypting and decrypting SOAP attachments as first-class parts of the message, under the
same key material as the body.

This is the [WSS SOAP Messages with Attachments (SwA) Profile 1.1](https://docs.oasis-open.org/wss-m/wss/v1.1.1/os/wss-SwAProfile-v1.1.1-os.html).
You most often meet it because a peer's WS-SecurityPolicy requires it: `sp:Attachments` under `sp:SignedParts`
or `sp:EncryptedParts`, which is what Apache CXF and WSS4J emit and enforce.

## What you need

Attachment handling itself lives in a separate package, so cryptography and MIME stay independent:

```bash
composer require php-soap/psr18-attachments-middleware
```

Version **0.11.0** or later. This package names it under `suggest`, never `require`: nothing about installing
WS-Security pulls in attachment handling, and nothing about using attachments pulls in cryptography.

## Wiring

```php
use Http\Client\Common\PluginClient;
use Soap\Psr18AttachmentsMiddleware\Attachment\Attachment;
use Soap\Psr18AttachmentsMiddleware\Middleware\AttachmentsMiddleware;
use Soap\Psr18AttachmentsMiddleware\Multipart\AttachmentType;
use Soap\Psr18AttachmentsMiddleware\Storage\AttachmentStorage;
use Soap\Psr18Transport\Psr18Transport;
use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\AttachmentParts;
use Soap\Psr18WsseMiddleware\WSSecurity\{Inbound, Outbound, Part, SecurityProfile};
use Soap\Psr18WsseMiddleware\WsseMiddleware;

// Keep this somewhere central: it is how you add and read attachments per call.
$attachments = new AttachmentStorage();

$transport = Psr18Transport::createForClient(
    new PluginClient($yourPsr18Client, [
        // WSSE first: it must see plain XML on the way out and a split multipart on the way back.
        new WsseMiddleware(
            new SecurityProfile(),
            outbound: [
                new Outbound\Timestamp(),
                // Sign first, so the digest covers the plaintext attachment.
                (new Outbound\Signature($clientCertificate))
                    ->withAttachments(AttachmentParts::request($attachments)),
                (new Outbound\Encryption($recipientCertificate))
                    ->withParts([Part::body()])
                    ->withAttachments(AttachmentParts::request($attachments)),
            ],
            inbound: [
                // Decrypt first, so the signature is verified against the plaintext.
                (new Inbound\Decrypt($privateKey))
                    ->withAttachments(AttachmentParts::response($attachments)),
                (new Inbound\VerifySignature($trustStore))
                    ->withAttachments(AttachmentParts::response($attachments)),
                new Inbound\ValidateTimestamp(),
            ],
        ),
        new AttachmentsMiddleware($attachments, AttachmentType::Swa),
    ])
);

// Attachments are added per call, before the request goes out.
$attachments->requestAttachments()->add(Attachment::cid(
    uri: 'invoice@example.com',
    name: 'invoice',
    filename: 'invoice.pdf',
    content: FileStream::create('/path/to/invoice.pdf', FileStream::READ_MODE),
));

$response = $client->request('Foo', $payload);

// Decrypted on the way in, with the original media type restored.
foreach ($attachments->responseAttachments() as $attachment) {
    $attachment->content->copyTo(
        FileStream::create('/tmp/'.$attachment->filename, FileStream::WRITE_MODE),
    );
}
```

Two ordering rules, and neither is cosmetic:

- **`WsseMiddleware` before `AttachmentsMiddleware`.** In a `PluginClient` the first plugin is the outermost,
  so this gives WSSE the request before it is packed into a multipart body and the response after it is split
  back out. The other order shows WSSE a multipart blob it cannot read.
- **Sign then encrypt outbound, decrypt then verify inbound.** The same rule the body already follows. The
  `ds:Reference` keeps naming `cid:invoice@example.com` while the part behind it becomes ciphertext, so inbound
  the plaintext has to be restored before the digest is checked. Any other inbound order fails.

Use `AttachmentParts::request()` on outbound blocks and `AttachmentParts::response()` on inbound ones. The two
collections are kept apart deliberately: an outbound block must never reach the parts that arrived with a
response.

## MTOM needs nothing extra

SwA and MTOM/XOP are one mechanism here. Both put the bytes in a MIME part addressed by `cid:`, and this
feature encrypts and signs MIME parts addressed by `cid:`. Nothing branches on `AttachmentType`.

That works because the attachments middleware owns both the attachment and the `xop:Include` tag and never
inlines base64. Outbound, the encoder puts the plaintext in the storage and an `<xop:Include href="cid:..."/>`
in the XML; this package encrypts the part in the storage and leaves the include alone. Inbound, the response
builder fills the storage with the ciphertext parts, this package decrypts them, and the engine then resolves
the include to the decrypted attachment. Decoding happens after the transport, and therefore after this
middleware, which is why nothing has to move.

**Measured, not argued.** The interop suite runs all four directions twice, once packaged as SwA and once as
MTOM, against a WSS4J peer: each side signs and the other verifies, each side encrypts and the other decrypts.
The MTOM encryption case also reads the part as it crossed the wire and asserts it was ciphertext there, which
is what would fail if the peer resolved the `xop:Include` before its security interceptor ran.

**MTOM here means SOAP 1.2.** The attachments middleware writes `start-info="application/soap+xml"` into an
MTOM `Content-Type` whatever the envelope says, and a SOAP 1.1 XOP package is one whose `start-info` is
`text/xml`, so a peer reading a SOAP 1.1 envelope out of an MTOM package refuses it before any security
processing happens. Pair `AttachmentType::Mtom` with a SOAP 1.2 envelope.

**One guard runs the other way.** Encrypting an *element* that contains an `xop:Include` is refused. The
ciphertext would cover the pointer while the file itself travelled in the clear in its own part, and the
message would still satisfy a policy check for that element being encrypted. Encrypting the *part* an include
points at is the supported path, and that is what `withAttachments()` does.

## Wire format

Next to an encrypted Body, an encrypted attachment looks like this:

```xml
<wsse:Security>
  <xenc:EncryptedKey>
    <xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"/>
    <ds:KeyInfo>...</ds:KeyInfo>
    <xenc:CipherData><xenc:CipherValue>...</xenc:CipherValue></xenc:CipherData>
    <xenc:ReferenceList>
      <xenc:DataReference URI="#EncData-body"/>
      <xenc:DataReference URI="#EncData-attachment"/>
    </xenc:ReferenceList>
  </xenc:EncryptedKey>
  <xenc:EncryptedData wsu:Id="EncData-attachment"
                      Type="http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Only"
                      MimeType="application/pdf">
    <xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
    <xenc:CipherData>
      <xenc:CipherReference URI="cid:invoice@example.com">
        <xenc:Transforms>
          <ds:Transform Algorithm="http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Ciphertext-Transform"/>
        </xenc:Transforms>
      </xenc:CipherReference>
    </xenc:CipherData>
  </xenc:EncryptedData>
</wsse:Security>
```

The MIME part keeps its `Content-ID`, its `Content-Type` becomes `application/octet-stream`, and its body is
the raw `IV || ciphertext || tag`: unencoded, because the MIME layer carries the bytes and nothing has to escape
them. The original media type travels on `@MimeType` so the receiver can restore it. This is what Apache WSS4J
emits, which is what CXF and Metro peers expect.

**One `xenc:EncryptedKey`, always.** Its single `xenc:ReferenceList` names the in-document parts and the
attachment parts together, so all of them are under one session key. That is why `withAttachments()` sits on
the same `Outbound\Encryption` block rather than being a block of its own: a second block would emit a second
key, which a receiver refuses.

A signed attachment adds a reference to the same `ds:Signature` as the body's:

```xml
<ds:Reference URI="cid:invoice@example.com">
  <ds:Transforms>
    <ds:Transform Algorithm="http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform"/>
  </ds:Transforms>
  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
  <ds:DigestValue>...</ds:DigestValue>
</ds:Reference>
```

One signature covering body and attachments together, which is the shape a far-side `sp:SignedParts` policy is
checked against. The digest is over the part's octets exactly as they travel: no canonicalization, no
transfer-encoding step. The profile says so, and the attachments middleware already sends
`Content-Transfer-Encoding: binary`, so the bytes on the wire are the bytes hashed. The URI is the part's
`cid:` verbatim, which binds each digest to one specific part: swapping two attachments is a digest mismatch
rather than a substitution nobody notices.

## What is refused, and why

| Case | Behaviour |
|---|---|
| Signing a `text/*` attachment | Refused. The profile normalizes line endings in text content before digesting, which is not implemented, so the signature would be one only this package can verify |
| Signing an XML attachment (`text/xml`, `application/xml`, or a `+xml` subtype of `application` or `image`) | Refused, for the same reason in its other form: the profile canonicalizes XML content with exclusive C14N before digesting. The set matches what a peer treats as XML, so a `+xml` subtype under any other top-level type is digested as opaque bytes by both sides |
| An attachment whose stream reads zero bytes | Refused. Encrypting nothing ships an empty file that passes every structural check on the far side. A stream that cannot rewind reads this way too |
| Encrypting an element that is or contains an `xop:Include` | Refused. See the MTOM section above |
| A registered attachment that no `ds:Reference` covers | Refused. Registering parts on `VerifySignature` is the requirement that they be signed |
| An encrypted attachment when none are registered on `Decrypt` | Refused, never skipped. Otherwise the message reads as decrypted while your code holds ciphertext |
| A `cid:` reference naming a part you did not supply | Refused. Never resolved, never fetched, under any circumstance |
| `Attachment-Complete`, in either direction | Refused. Covering the MIME headers needs header canonicalization this release does not implement, so the mode is refused rather than approximated |
| A cipher reference declaring no transform, several, or the wrong one | Refused before any decryption |
| A data-encryption method outside the profile's allow-list | Refused. An external part gets the same allow-list as an in-document one, CBC refusal included |
| Two attachments sharing a `Content-ID` | Refused. One reference must address one part |

Inbound, every one of these collapses into the same `SecurityFault` as the rest of the inbound path, so the
attachment path is no more of an oracle than the body's. Outbound failures are `EncryptionFailed` or
`SigningFailed` and do state a reason: nothing about your own outbound message is a secret from you.

## Limits

- **Whole parts are buffered.** The cipher takes and returns strings, so an attachment is held in memory around
  twice at peak. That matches what the attachments middleware already implies by building the multipart body in
  memory. Attachments comfortably smaller than available memory are the supported case.
- **`Attachment-Complete` is not implemented**, for signing or for encryption. If a peer's policy demands
  `sp:AttachmentComplete` or `sp13:AttachmentCompleteSignatureTransform`, this package cannot satisfy it today.
- **WCF and .NET cannot be the peer.** There is no SwA support in WCF, only MTOM. A .NET peer that wants
  attachment security is not a case this feature serves.

## Writing your own adapter

`AttachmentParts` is a thin adapter over one storage, and the seam it implements is public:

```php
interface ExternalParts
{
    public function coverage(): ExternalPartCoverage;
    public function collect(): ExternalPartList;
    public function replace(ExternalPartList $parts): void;
}
```

Implement it if your attachments live somewhere else. Three contract points matter:

- **`coverage()` says how much of a part your compositions cover.** Return `ExternalPartCoverage::Content`:
  it is the only coverage this release implements, and no block reads the value yet. The method is on the
  seam so that adding `Complete` later is a change to implementations rather than to the interface, which
  would break every one of them at once.
- **`collect()` may be called more than once per message, so rewind on every collect.** Sign-then-encrypt
  collects twice: the signature digests the plaintext, then encryption seals the same plaintext. The engine
  rewinds each part before reading it as well, so a spent stream is recovered rather than sealed empty, but do
  not lean on that: it is defence in depth, and a stream that cannot rewind reads as zero bytes and is refused.
- **`replace()` fully replaces the parts it is handed, matched by reference, and touches nothing else.**
  Inbound it receives only the parts an `xenc:EncryptedData` actually named, so an attachment that arrived in
  the clear is absent from the list and must be left as it is rather than dropped.
