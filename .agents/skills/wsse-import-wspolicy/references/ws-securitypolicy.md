# The WS-SecurityPolicy assertions

## Versions and namespaces

| Namespace | Version |
|---|---|
| `http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702` | WS-SecurityPolicy 1.2 and 1.3, the OASIS standard, what you will normally meet |
| `http://schemas.xmlsoap.org/ws/2005/07/securitypolicy` | The 2005 pre-OASIS submission, still found in older WSDLs |

The `sp:IncludeToken` attribute value carries the same prefix, so it also tells you which version you are
reading. Policy framework elements (`wsp:Policy`, `wsp:ExactlyOne`, `wsp:All`, `wsp:PolicyReference`) come from
WS-Policy, conventionally the `wsp:` prefix.

## Shape

A real example, from the OASIS use-case document, of the case you will meet most often: asymmetric binding,
X.509 both ways, plus a UsernameToken.

```xml
<wsp:Policy wsu:Id="wss10_up_cert_policy">
  <wsp:ExactlyOne>
    <wsp:All>
      <sp:AsymmetricBinding>
        <wsp:Policy>
          <sp:InitiatorToken>
            <wsp:Policy>
              <sp:X509Token sp:IncludeToken="http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient">
                <wsp:Policy>
                  <sp:WssX509V3Token10/>
                </wsp:Policy>
              </sp:X509Token>
            </wsp:Policy>
          </sp:InitiatorToken>
          <sp:RecipientToken>
            <wsp:Policy>
              <sp:X509Token sp:IncludeToken="http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/Never">
                <wsp:Policy>
                  <sp:WssX509V3Token10/>
                </wsp:Policy>
              </sp:X509Token>
            </wsp:Policy>
          </sp:RecipientToken>
          <sp:AlgorithmSuite>
            <wsp:Policy>
              <sp:Basic256/>
            </wsp:Policy>
          </sp:AlgorithmSuite>
          <sp:Layout>
            <wsp:Policy>
              <sp:Strict/>
            </wsp:Policy>
          </sp:Layout>
          <sp:IncludeTimestamp/>
          <sp:OnlySignEntireHeadersAndBody/>
        </wsp:Policy>
      </sp:AsymmetricBinding>
      <sp:Wss10>
        <wsp:Policy>
          <sp:MustSupportRefKeyIdentifier/>
        </wsp:Policy>
      </sp:Wss10>
      <sp:SignedEncryptedSupportingTokens>
        <wsp:Policy>
          <sp:UsernameToken sp:IncludeToken="http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient">
            <wsp:Policy>
              <sp:WssUsernameToken10/>
            </wsp:Policy>
          </sp:UsernameToken>
        </wsp:Policy>
      </sp:SignedEncryptedSupportingTokens>
    </wsp:All>
  </wsp:ExactlyOne>
</wsp:Policy>
```

Two structural points before any mapping:

- **`wsp:ExactlyOne` holding several `wsp:All` blocks offers alternatives.** The service accepts any one of them.
  Pick one, name it in the output, and prefer the alternative with the strongest algorithms.
- **The attachment point decides direction.** Assertions inside the binding apply both ways. A policy attached to
  `wsdl:input` constrains the request, which is your `outbound`; one attached to `wsdl:output` constrains the
  response, which is your `inbound`. A `wsp:PolicyReference` must be followed before you can claim to have read
  the policy.

## Bindings

| Assertion | Ours |
|---|---|
| `sp:TransportBinding` | TLS protects the message, so usually no `Signature` and no `Encryption` block at all. Read the nested `sp:IncludeTimestamp` and any supporting tokens and stop there. The commonest real-world policy, and the one people over-implement. |
| `sp:AsymmetricBinding` | The signing and encryption case. `sp:InitiatorToken` is your identity, `sp:RecipientToken` is the peer you encrypt to. |
| `sp:SymmetricBinding` | One key source passed to both blocks. `sp:ProtectionToken` names the key; see Symmetric bindings below for the whole mapping. Note the shape difference: an asymmetric binding gives each block its own credential, a symmetric one gives both blocks the same object. |

Inside a binding:

| Assertion | Ours |
|---|---|
| `sp:IncludeTimestamp` | `new Outbound\Timestamp()`, and `Part::timestamp()` among the signed parts, which the default part list already covers |
| `sp:Layout` with `sp:Strict`, `sp:Lax`, `sp:LaxTsFirst`, `sp:LaxTsLast` | No setting. Node order in the Security header is fixed here. `sp:Strict` is what this package emits; the others impose no requirement it can violate. |
| `sp:OnlySignEntireHeadersAndBody` | Already true. Every `Part` names a whole element, so partial-element signing is not representable. |
| `sp:SignBeforeEncrypting` or absent | The default, and the block order this package requires: `Signature` then `Encryption`. |
| `sp:EncryptBeforeSigning` | Reverse the block order: `Encryption` then `Signature`. Flag it, because it is unusual and worth confirming against a captured message. |
| `sp:EncryptSignature` | Unmapped. This package does not encrypt the `ds:Signature`. |
| `sp:ProtectTokens` | Partly covered: the default signed-part list includes `Part::securityHeaderContents()`, which covers an embedded token. Confirm rather than assume, and raise it if the signing token is referenced instead of embedded. |
| `sp:EncryptedParts` / `sp:SignedParts` | See Parts below |

## AlgorithmSuite

Expand the suite from this table. **Do not infer it from the name**: the `Sha256` in `Basic256Sha256` is the
digest, and the signature is RSA-SHA1 in every standard suite.

| Suite | Digest | Data cipher | Asymmetric key wrap |
|---|---|---|---|
| `sp:Basic256` | Sha1 | Aes256 | KwRsaOaep |
| `sp:Basic192` | Sha1 | Aes192 | KwRsaOaep |
| `sp:Basic128` | Sha1 | Aes128 | KwRsaOaep |
| `sp:TripleDes` | Sha1 | TripleDes | KwRsaOaep |
| `sp:Basic256Rsa15` | Sha1 | Aes256 | KwRsa15 |
| `sp:Basic192Rsa15` | Sha1 | Aes192 | KwRsa15 |
| `sp:Basic128Rsa15` | Sha1 | Aes128 | KwRsa15 |
| `sp:TripleDesRsa15` | Sha1 | TripleDes | KwRsa15 |
| `sp:Basic256Sha256` | Sha256 | Aes256 | KwRsaOaep |
| `sp:Basic192Sha256` | Sha256 | Aes192 | KwRsaOaep |
| `sp:Basic128Sha256` | Sha256 | Aes128 | KwRsaOaep |
| `sp:TripleDesSha256` | Sha256 | TripleDes | KwRsaOaep |
| `sp:Basic256Sha256Rsa15` | Sha256 | Aes256 | KwRsa15 |
| `sp:Basic192Sha256Rsa15` | Sha256 | Aes192 | KwRsa15 |
| `sp:Basic128Sha256Rsa15` | Sha256 | Aes128 | KwRsa15 |
| `sp:TripleDesSha256Rsa15` | Sha256 | TripleDes | KwRsa15 |

Every suite specifies **RsaSha1** for asymmetric signatures and **HmacSha1** for symmetric ones. No standard
suite selects RSA-SHA256 or HMAC-SHA256; CXF and other stacks offer a non-policy property to override it, so if
the peer signs with SHA-256 the policy will not say so and you must confirm against a captured message. Which of
the two a suite's signature token means depends on the binding: an asymmetric binding signs with RsaSha1, a
symmetric one with HmacSha1.

Each token maps to one of our cases:

| Suite token | Ours |
|---|---|
| Sha1 | `DigestMethod::SHA1` |
| Sha256 | `DigestMethod::SHA256` |
| Aes256 / Aes192 / Aes128 | `DataEncryptionMethod::AES256_CBC` / `AES192_CBC` / `AES128_CBC` |
| TripleDes | `DataEncryptionMethod::TRIPLEDES_CBC` |
| KwRsaOaep | `KeyEncryptionMethod::RSA_OAEP_MGF1P`, the legacy `rsa-oaep-mgf1p` URI, **not** `RSA_OAEP` |
| KwRsa15 | `KeyEncryptionMethod::RSA_1_5` |
| RsaSha1 | `SignatureMethod::RSA_SHA1` |
| HmacSha1 | `SignatureMethod::HMAC_SHA1`, for a symmetric binding. Refused by the default `CryptoPolicy` exactly as `RsaSha1` is, so it needs naming in `acceptedSignatureMethods` with a comment saying which suite forced it. The SHA-2 sizes (`HMAC_SHA256/384/512`) are accepted by default, so a peer that will move off SHA-1 needs no allow-list entry at all. |
| Canonicalization | `SignatureCanonicalization::EXC_C14N`, which the suites fix and which is already our default |

**Read this before writing the profile.** Against our defaults, a faithful `sp:Basic256` import needs three
downgrades: SHA-1 digest, AES-CBC data cipher and RSA-SHA1 signature. `sp:Basic256Sha256` still needs two. Each
one is refused by the default `CryptoPolicy` for a reason recorded in `docs/security-profile.md`, and each needs
a comment naming the assertion that forced it, on both the outbound choice and the inbound allow-list. AES-CBC in
particular is unauthenticated: say so in the comment rather than letting it pass as an algorithm name.

## Tokens

| Assertion | Ours |
|---|---|
| `sp:InitiatorToken` with `sp:X509Token` | Your signing identity: `new Outbound\Signature(new Signing\Asymmetric($clientCertificate))` |
| `sp:RecipientToken` with `sp:X509Token` | The peer's certificate: `new Outbound\Encryption(new Keys\GeneratedSessionKey($recipientCertificate))` |
| `sp:ProtectionToken` with `sp:X509Token` | A symmetric binding's key: `new Keys\GeneratedSessionKey($recipientCertificate)`, passed to **both** blocks. See Symmetric bindings below. |
| `sp:WssX509V3Token10` / `sp:WssX509V3Token11` | An X.509 v3 certificate, which is what this package sends |
| `sp:WssX509PkiPathV1Token10` | `new Signing\Asymmetric($clientCertificate, path: $chain)`, which sends the chain as `X509PKIPathv1` |
| `sp:UsernameToken` with `sp:WssUsernameToken10` | `new Outbound\Username($user, $password)`, `PasswordText` |
| `sp:HashPassword` | `->withDigest(true)` |
| `sp:NoPassword` | `new Outbound\Username($user)`, a username-only token |
| `sp:SupportingTokens`, `sp:SignedSupportingTokens`, `sp:SignedEncryptedSupportingTokens` | The token goes in the header; the wrapper says whether it must also be signed and encrypted. `Signed*` means adding `Part::usernameToken()` to the signed parts, `*Encrypted*` means adding it to the encrypted parts. |
| `sp:IssuedToken` with `sp:RequestSecurityTokenTemplate` | A SAML assertion from an STS. `new Outbound\SamlAssertion($xml, $version)` imports one you already hold; obtaining it is out of scope. Ask where it comes from. |
| `sp:EndorsingSupportingTokens`, `sp:SignedEndorsingSupportingTokens` | A second `Signature` block over `Part::primarySignature()`, placed after the block it endorses: `(new Outbound\Signature(new Signing\Asymmetric($clientCertificate, KeyRef::Thumbprint)))->withParts([Part::primarySignature()])`. `Signed*` additionally means the endorsing token itself must be covered by the primary signature, so add `Part::binarySecurityToken()` there. Expect one alongside a symmetric binding: without it the request authenticates nobody. |
| `sp:KerberosToken`, `sp:SpnegoContextToken`, `sp:SecureConversationToken` | Unmapped. `sp:SecureConversationToken` needs an RST/RSTR handshake with the service, which this package does not perform; the `wsc:DerivedKeyToken` half of WS-SecureConversation is supported and reachable through `sp:RequireDerivedKeys`, the handshake is not. |
| `sp:Trust13` / `sp:Trust10` | WS-Trust negotiation with an STS, not something this package performs. |

`sp:IncludeToken` says whether the token travels with the message:

| Value | Meaning | Ours |
|---|---|---|
| `.../IncludeToken/Never` | The token is not sent; the peer resolves it from a reference | A key reference that carries no token: SKI, Issuer/Serial or Thumbprint, per the reference assertions below |
| `.../IncludeToken/AlwaysToRecipient` | Sent on every message to the recipient | `KeyRef::BinarySecurityToken`, the embedded token |
| `.../IncludeToken/Once` | Sent once per exchange | Treated as `AlwaysToRecipient`, since this package has no cross-message state. Note it. |
| `.../IncludeToken/AlwaysToInitiator` | The recipient sends its token to you | An inbound concern; nothing to configure outbound |

## Key references

Nested inside a token assertion:

| Assertion | Ours |
|---|---|
| `sp:RequireKeyIdentifierReference` | `KeyRef::SubjectKeyIdentifier` / `EncKeyRef::SubjectKeyIdentifier` |
| `sp:RequireIssuerSerialReference` | `IssuerSerial` |
| `sp:RequireThumbprintReference` | `Thumbprint` |
| `sp:RequireEmbeddedTokenReference` | Unmapped, an embedded token reference |

**More than one is a conflict you must raise.** The specification says that when a token assertion carries
several reference assertions, references to that token must use *all* of them. This package emits exactly one key
reference per block, so a policy demanding two cannot be satisfied. Do not silently pick one: report it and ask
which the peer actually enforces.

`sp:Wss10` and `sp:Wss11` with their `sp:MustSupportRef*` children are a common misreading. They state what a
receiver must be *able to accept*, not what the sender must emit, so they constrain nothing about your outbound
key reference. Use them only to widen what you are prepared to see inbound. `sp:Wss11` additionally allows
`sp:RequireSignatureConfirmation`, which is unmapped: this package does not emit `wsse11:SignatureConfirmation`.

## Parts

| Assertion | Ours |
|---|---|
| `sp:SignedParts` with `sp:Body` | `Part::body()` |
| `sp:EncryptedParts` with `sp:Body` | `Part::body()`, which already encrypts in `EncryptionMode::Content`, matching the assertion's meaning of the Body's content |
| `sp:Header Name="X" Namespace="urn:y"` | `Part::element('urn:y', 'X')` |
| `sp:Header Namespace="urn:y"` with no `Name` | Every header in that namespace. No direct equivalent: `Part::soapHeaders()` covers all SOAP headers except the Security header, which is usually wider. Say so if you use it. |
| An empty `sp:SignedParts` / `sp:EncryptedParts` | Nothing is required by that assertion; do not invent parts |
| `sp:SignedElements` / `sp:EncryptedElements` with `sp:XPath` | `Part::path(...)` when the expression is a chain of single elements from the document element down, `Part::element()` when a qualified name anywhere will do. Anything else is unmapped: ask which element is meant. |
| `sp:RequiredElements` with `sp:XPath` | A presence requirement, not a protection requirement. Nothing to configure. |
| `sp:Attachments` under `sp:SignedParts`, with no child | `withAttachments(AttachmentParts::request($storage, ExternalPartCoverage::Complete))` on `Outbound\Signature`, plus the same on `Inbound\VerifySignature` with `::response()`. **The absence of `sp13:ContentSignatureTransform` means the complete coverage**, so reading a bare `sp:Attachments` as content-only generates a configuration that cannot work against the WSDL it came from. See [Attachment security](../../../../docs/attachments.md) |
| `sp13:ContentSignatureTransform` inside `sp:Attachments` | The content coverage: `AttachmentParts::request($storage, ExternalPartCoverage::Content)`. This is what AS4 and eDelivery peers set |
| `sp13:AttachmentCompleteSignatureTransform` inside `sp:Attachments` | `ExternalPartCoverage::Complete`, the same as a bare `sp:Attachments`. Spelling it out changes nothing |
| `sp:Attachments` under `sp:EncryptedParts` | `withAttachments(AttachmentParts::request($storage, ExternalPartCoverage::Content))` on `Outbound\Encryption`, plus `withAttachments(AttachmentParts::response($storage, ExternalPartCoverage::Complete))` on `Inbound\Decrypt`. **The element takes no children here**, unlike under `sp:SignedParts`, so the policy language has no way to ask for one coverage over the other and content-only always conforms. Emit the content one and accept the complete one: a default-configured CXF sender emits it |

### MTOM in the policy changes the inbound list, and no security assertion says so

`wsoma:OptimizedMimeSerialization` (or a CXF `mtom-enabled` property in the accompanying config) is not a
security assertion, so it maps to nothing above. Read it anyway: a peer with MTOM enabled puts the bytes of an
`xenc:CipherValue` in a MIME part and leaves an `xop:Include` behind, because Apache CXF turns
`storeBytesInAttachment` on by itself in that case, and .NET and Metro do the same to any large encrypted
content without being configured to. There is no assertion for it, nothing negotiates it, and it applies to
every encrypted message rather than only the ones with attachments.

So whenever the policy asks for encryption **and** the peer is MTOM-enabled, the import needs one more inbound
block, first in the list:

```php
new Inbound\ResolveOptimizedBytes(
    AttachmentParts::response($storage, ExternalPartCoverage::Content),
),
```

Without it such a response is refused as a cipher value that will not decode, and the fault says nothing about
why. Say so when you report the mapping, and say that it is inferred from MTOM rather than read off an
assertion. The outbound counterpart, `withOptimizedCipherBytes()`, is never implied by a policy: no assertion
can require it, so it stays a deployment choice about size.

`sp:Attachments` requires `php-soap/psr18-attachments-middleware` 0.12.0 or later and an `AttachmentStorage`
shared with `AttachmentsMiddleware`, so importing one means adding a dependency and a second middleware, not
just a `with*()` call. Say so when you report the mapping. A `text/*` attachment is signed over a transformed form of its
content, XML with exclusive C14N and any other text with its line endings normalized, so the only such policy
that cannot be satisfied is one whose XML attachment is not a well-formed document or carries a doctype.

The signing default is `[Part::body(), Part::securityHeaderContents()]` and the encryption default is
`[Part::body()]`. A policy asking for exactly the Body plus the timestamp and tokens is already the default, so
write no `withParts()` call.

## Symmetric bindings

An `sp:SymmetricBinding` keys the signature and the encryption off one symmetric key. The mapping is expressed by
**passing one key-source object to both blocks**; nothing says "share".

| Assertion | Ours |
|---|---|
| `sp:ProtectionToken` with `sp:X509Token` | `new Keys\GeneratedSessionKey($recipientCertificate, EncKeyRef::Thumbprint)` (or whichever `EncKeyRef` the nested `sp:Require*Reference` names). A fresh session key per exchange, carried in an `xenc:EncryptedKey`. |
| `sp:ProtectionToken` naming a key agreed out of band | `new Keys\PreSharedSessionKey($secret, $identifier, $valueType)`. Ask where the secret and the agreed identifier come from; neither is in the policy. |
| `sp:RequireDerivedKeys` | Wrap the source in `new Keys\DerivedSessionKey($source)` **per block**, not once and shared. Each block derives a key of its own length, and two `DerivedSessionKey` objects over one `GeneratedSessionKey` are the two `wsc:DerivedKeyToken` off one `xenc:EncryptedKey` the policy describes. |
| `sp:EncryptSignature` | Still unmapped. This package does not encrypt the `ds:Signature`. |
| `sp:AlgorithmSuite` signature token | `HmacSha1` here, not `RsaSha1`. See the AlgorithmSuite table. |

The signature block takes the source through a `Signing\Symmetric`:

```php
$protection = new Keys\GeneratedSessionKey($recipientCertificate, EncKeyRef::Thumbprint);

new WsseMiddleware($profile, outbound: [
    new Outbound\Timestamp(),
    (new Outbound\Signature(new Signing\Symmetric(new Keys\DerivedSessionKey($protection))))
        ->withSignatureMethod(SignatureMethod::HMAC_SHA1)   // sp:Basic128Rsa15 pins this
        ->withParts([Part::body(), Part::timestamp()]),
    (new Outbound\Encryption(new Keys\DerivedSessionKey($protection)))
        ->withDataEncryptionMethod(DataEncryptionMethod::AES128_CBC)
        ->withParts([Part::body()]),
    (new Outbound\Signature(new Signing\Asymmetric($clientCertificate, KeyRef::Thumbprint)))
        ->withParts([Part::primarySignature()]),            // sp:EndorsingSupportingTokens
]);
```

Three rules to carry into the draft:

- **Block order is not free.** The signature comes before the encryption as usual, and an endorsing signature
  comes after the block it endorses. An endorsing block placed earlier throws rather than signing nothing.
- **Say what the binding does not authenticate.** A request protected only by a `GeneratedSessionKey` signature
  proves possession of nothing: anyone holding the recipient's public certificate can mint a key and wrap it. If
  the policy carries no endorsing supporting token, raise that as a question rather than shipping it silently.
  A `PreSharedSessionKey` does authenticate, mutually.
- **`Basic128Rsa15` and its siblings pin two refused algorithms**, not one: RSA-1.5 key transport and HMAC-SHA1.
  Both need naming in the allow-lists with a comment, and both are worth renegotiating.

The inbound direction usually needs nothing extra: a response keyed by the same key resolves it from the
exchange. A `PreSharedSessionKey` is the exception, and has to be handed to the inbound blocks with
`new Inbound\Decrypt(preSharedKey: $secret)` and `new Inbound\VerifySignature($trustStore, $secret)`, because
no outbound direction established it.
