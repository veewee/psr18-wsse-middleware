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
| `sp:SymmetricBinding` | Largely unmapped. It protects with one shared symmetric key, named by `sp:ProtectionToken`, often with derived keys. This package always signs asymmetrically and wraps a fresh session key per message. Raise it as a question rather than approximating. |

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

Every suite specifies **RsaSha1** for asymmetric signatures and HmacSha1 for symmetric ones. No standard suite
selects RSA-SHA256; CXF and other stacks offer a non-policy property to override it, so if the peer signs with
SHA-256 the policy will not say so and you must confirm against a captured message.

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
| HmacSha1 | Unmapped. Symmetric signatures are not supported. |
| Canonicalization | `SignatureCanonicalization::EXC_C14N`, which the suites fix and which is already our default |

**Read this before writing the profile.** Against our defaults, a faithful `sp:Basic256` import needs three
downgrades: SHA-1 digest, AES-CBC data cipher and RSA-SHA1 signature. `sp:Basic256Sha256` still needs two. Each
one is refused by the default `CryptoPolicy` for a reason recorded in `docs/security-profile.md`, and each needs
a comment naming the assertion that forced it, on both the outbound choice and the inbound allow-list. AES-CBC in
particular is unauthenticated: say so in the comment rather than letting it pass as an algorithm name.

## Tokens

| Assertion | Ours |
|---|---|
| `sp:InitiatorToken` with `sp:X509Token` | Your signing identity: `new Outbound\Signature($clientCertificate)` |
| `sp:RecipientToken` with `sp:X509Token` | The peer's certificate: `new Outbound\Encryption($recipientCertificate)` |
| `sp:WssX509V3Token10` / `sp:WssX509V3Token11` | An X.509 v3 certificate, which is what this package sends |
| `sp:WssX509PkiPathV1Token10` | `Signature::withCertificatePath($chain)`, which sends the chain as `X509PKIPathv1` |
| `sp:UsernameToken` with `sp:WssUsernameToken10` | `new Outbound\Username($user, $password)`, `PasswordText` |
| `sp:HashPassword` | `->withDigest(true)` |
| `sp:NoPassword` | `new Outbound\Username($user)`, a username-only token |
| `sp:SupportingTokens`, `sp:SignedSupportingTokens`, `sp:SignedEncryptedSupportingTokens` | The token goes in the header; the wrapper says whether it must also be signed and encrypted. `Signed*` means adding `Part::usernameToken()` to the signed parts, `*Encrypted*` means adding it to the encrypted parts. |
| `sp:IssuedToken` with `sp:RequestSecurityTokenTemplate` | A SAML assertion from an STS. `new Outbound\SamlAssertion($xml, $version)` imports one you already hold; obtaining it is out of scope. Ask where it comes from. |
| `sp:KerberosToken`, `sp:SpnegoContextToken`, `sp:SecureConversationToken` | Unmapped. |
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
| `sp13:ContentSignatureTransform` inside `sp:Attachments` | The content coverage, which is the argument's default: `AttachmentParts::request($storage)`. This is what AS4 and eDelivery peers set |
| `sp13:AttachmentCompleteSignatureTransform` inside `sp:Attachments` | `ExternalPartCoverage::Complete`, the same as a bare `sp:Attachments`. Spelling it out changes nothing |
| `sp:Attachments` under `sp:EncryptedParts` | `withAttachments(AttachmentParts::request($storage))` on `Outbound\Encryption`, plus `withAttachments(AttachmentParts::response($storage, ExternalPartCoverage::Complete))` on `Inbound\Decrypt`. Either coverage satisfies the policy, since a peer never validates the coverage of an encryption, so emit the content one and accept the complete one: a default-configured CXF sender emits it |
| `sp:AttachmentComplete` | The complete coverage for encryption. Inbound that is `ExternalPartCoverage::Complete` on `Inbound\Decrypt`. Outbound it is **unmapped**: emitting complete ciphertext is not implemented, and no policy can require it, so report the assertion and configure the content coverage |

`sp:Attachments` requires `php-soap/psr18-attachments-middleware` 0.12.0 or later and an `AttachmentStorage`
shared with `AttachmentsMiddleware`, so importing one means adding a dependency and a second middleware, not
just a `with*()` call. Say so when you report the mapping. Note also that a policy pairing `sp:Attachments`
under `sp:SignedParts` with a `text/*` attachment cannot be satisfied: signing those is refused.

The signing default is `[Part::body(), Part::securityHeaderContents()]` and the encryption default is
`[Part::body()]`. A policy asking for exactly the Body plus the timestamp and tokens is already the default, so
write no `withParts()` call.
