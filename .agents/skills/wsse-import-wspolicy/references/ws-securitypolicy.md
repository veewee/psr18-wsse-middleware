# The WS-SecurityPolicy assertions

## Versions and namespaces

| Namespace | Version |
|---|---|
| `http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702` | WS-SecurityPolicy 1.2 and 1.3, the OASIS standard, what you will normally meet |
| `http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200512` | The committee draft between the two. Shipped in every WebSphere policy set, so common in IBM shops and rare elsewhere |
| `http://schemas.xmlsoap.org/ws/2005/07/securitypolicy` | The 2005 pre-OASIS submission, still found in older WSDLs |

The `wsp:` prefix has two values too: `http://www.w3.org/ns/ws-policy` (WS-Policy 1.5, what CXF and Metro write)
and `http://schemas.xmlsoap.org/ws/2004/09/policy` (WS-Policy 1.2, what WebSphere writes). Match on the local
names rather than on either namespace, because a document uses one and grepping for the other finds an empty
policy where there is a full one.

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

### The split you will actually meet

The single policy above is the documentation shape. A generated WSDL, from CXF or Metro alike, nearly always
splits it in three and references each part by id:

```xml
<wsdl:binding name="DoubleItBinding" type="tns:DoubleItPortType">
  <wsp:PolicyReference URI="#DoubleItAsymmetricPolicy"/>          <!-- binding: both directions -->
  <wsdl:operation name="DoubleIt">
    <wsdl:input>
      <wsp:PolicyReference URI="#DoubleItBinding_DoubleIt_Input_Policy"/>   <!-- outbound parts -->
    </wsdl:input>
    <wsdl:output>
      <wsp:PolicyReference URI="#DoubleItBinding_DoubleIt_Output_Policy"/>  <!-- inbound parts -->
    </wsdl:output>
  </wsdl:operation>
</wsdl:binding>
```

Read all three, and read them into different places:

| Where the policy hangs | What it carries | Where it lands |
|---|---|---|
| `wsdl:binding` | the binding, the tokens, the algorithm suite, `sp:IncludeTimestamp` | the profile, and both lists |
| `wsdl:input` | `sp:SignedParts` / `sp:EncryptedParts` | `withParts()` on the outbound blocks |
| `wsdl:output` | `sp:SignedParts` / `sp:EncryptedParts` | **`signed:` on `Inbound\VerifySignature`** |

The third row is the one that gets dropped. The response's `sp:SignedParts` is the only thing that tells you
what to require inbound, and `signed:` defaults to the body alone, so an output policy naming a header means a
`signed:` list you have to write. The two directions are commonly identical, and you still have to look: a
`wsdl:output` with no policy at all means the response is unprotected, which is worth raising rather than
mirroring the request.

## Bindings

| Assertion | Ours |
|---|---|
| `sp:TransportBinding` | TLS protects the message, so usually no `Signature` and no `Encryption` block at all. Read the nested `sp:IncludeTimestamp` and any supporting tokens and stop there. The commonest real-world policy, and the one people over-implement. |
| `sp:AsymmetricBinding` | The signing and encryption case. `sp:InitiatorToken` is your identity, `sp:RecipientToken` is the peer you encrypt to. **Both blocks only if both are asked for**: an alternative carrying `sp:SignedParts` and no `sp:EncryptedParts` is sign-only, so there is no `Encryption` block and the `sp:RecipientToken` goes unused. The binding names the tokens; the parts assertions decide which blocks exist. |
| `sp:SymmetricBinding` | One key source passed to both blocks. `sp:ProtectionToken` names the key; see Symmetric bindings below for the whole mapping. Note the shape difference: an asymmetric binding gives each block its own credential, a symmetric one gives both blocks the same object. |

Inside a binding:

| Assertion | Ours |
|---|---|
| `sp:IncludeTimestamp` | `new Outbound\Timestamp()`, and `Part::timestamp()` among the signed parts, which the default part list already covers |
| **no** `sp:IncludeTimestamp` | No `Timestamp` block and no `Inbound\ValidateTimestamp`. Adding them anyway is the commonest over-implementation: a peer that did not ask for a timestamp may refuse the header element, and validating one the peer never sends refuses every response. Plenty of real policies omit it. |
| An empty nested `wsp:Policy` on a token | Nothing is forced. Not an error and not something to fill in: take the defaults, and let `sp:IncludeToken` alone decide the key reference. |
| `sp:Layout` with `sp:Strict`, `sp:Lax`, `sp:LaxTsFirst`, `sp:LaxTsLast` | No setting. Node order in the Security header is fixed here. `sp:Strict` is what this package emits; the others impose no requirement it can violate. |
| `sp:OnlySignEntireHeadersAndBody` | Already true. Every `Part` names a whole element, so partial-element signing is not representable. |
| `sp:SignBeforeEncrypting` or absent | The default, and the block order this package requires: `Signature` then `Encryption`. |
| `sp:EncryptBeforeSigning` | Reverse the block order: `Encryption` then `Signature`. Flag it, because it is unusual and worth confirming against a captured message. |
| `sp:EncryptSignature` | Unmapped. This package does not encrypt the `ds:Signature`. |
| `sp:ProtectTokens` | Partly covered outbound: the default signed-part list includes `Part::securityHeaderContents()`, which covers an embedded token. Confirm rather than assume, and raise it if the signing token is referenced instead of embedded. **Do not turn it into an inbound requirement.** `Part::securityHeaderContents()` in `signed:` is not satisfied by an endorsing token's own element: an endorsement's coverage is deliberately not reported, so only what the endorsing party vouched for is discarded, and a peer that endorses under `sp:ProtectTokens` covers exactly that. Require the parts the sending party signed instead. |
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
| `sp:WssX509V1Token10` / `sp:WssX509V1Token11` | An X.509 **v1** certificate. Nothing to configure: the token carries whatever version your certificate is, so this is a requirement on the certificate rather than on the wiring. Raise it if yours is a v3, which it almost certainly is. |
| `sp:WssX509PkiPathV1Token10` / `sp:WssX509PkiPathV1Token11` | `new Signing\Asymmetric($clientCertificate, path: $chain)`, which sends the chain as `X509PKIPathv1`. Where the token signs nothing, see `sp:SupportingTokens` below. |
| `sp:SamlToken` with `sp:WssSamlV11Token10` or `sp:WssSamlV20Token11` | `new Outbound\SamlAssertion($xml, SamlVersion::Saml11 / ::Saml20)`. The token-type assertion is what tells you the version, which the block requires and never infers. Where the assertion comes from is not in the policy: ask. Under a `sp:Signed*SupportingTokens` wrapper this is a conflict to raise rather than a mapping, because signing the assertion stamps a `wsu:Id` inside what the issuer's own signature covers; see [Outbound blocks](../../../../docs/outbound-blocks.md#outbound-samlassertion). |
| `sp:UsernameToken` with `sp:WssUsernameToken10` | `new Outbound\Username($user, $password)`, `PasswordText` |
| `sp:HashPassword` | `->withDigest(true)` |
| `sp:NoPassword` | `new Outbound\Username($user)`, a username-only token |
| `sp:SupportingTokens`, `sp:SignedSupportingTokens`, `sp:SignedEncryptedSupportingTokens` | The token goes in the header; the wrapper says whether it must also be signed and encrypted. `Signed*` means adding the token's `Part` to the signed parts, `*Encrypted*` means adding it to the encrypted parts. `Part::usernameToken()` for a `sp:UsernameToken`, `Part::binarySecurityToken()` for an `sp:X509Token`. |
| `sp:SupportingTokens` with an `sp:X509Token` and no signature in the alternative | The certificate travels and signs nothing: `new Outbound\BinarySecurityToken($clientCertificate->publicCertificate())`, or `Outbound\BinarySecurityToken::forCertificatePath($chain)` for a PkiPath token type. Reach for this rather than inventing a `Signature` block the policy never asked for. Common under an `sp:TransportBinding`, where the token is an identity claim and TLS does the protecting. |
| `sp:IssuedToken` with `sp:RequestSecurityTokenTemplate` | A SAML assertion from an STS. `new Outbound\SamlAssertion($xml, $version)` imports one you already hold; obtaining it is out of scope. Ask where it comes from. |
| `sp:EndorsingSupportingTokens`, `sp:SignedEndorsingSupportingTokens` | A second `Signature` block over `Part::primarySignature()`, placed after the block it endorses: `(new Outbound\Signature(new Signing\Asymmetric($clientCertificate, KeyRef::Thumbprint)))->withParts([Part::primarySignature()])`. Its `sp:AlgorithmSuite` signature is the asymmetric one, `RsaSha1`, even under a symmetric binding whose primary signature is an HMAC. `Signed*` additionally means the endorsing token itself must be covered by the primary signature, so add `Part::binarySecurityToken()` there. Expect one alongside a symmetric binding: without it the request authenticates nobody. **Under an `sp:TransportBinding` it means something else entirely**: see below. |
| `sp:KerberosToken`, `sp:SpnegoContextToken`, `sp:SecureConversationToken` | Unmapped. `sp:SecureConversationToken` needs an RST/RSTR handshake with the service, which this package does not perform; the `wsc:DerivedKeyToken` half of WS-SecureConversation is supported and reachable through `sp:RequireDerivedKeys`, the handshake is not. |
| `sp:SecureConversationToken` **as the `sp:ProtectionToken`** | Not one unmapped assertion but an unmappable alternative: the key that protects every message is the one the handshake would establish, so there is nothing left to key the blocks off. Say that the alternative cannot be implemented and look for another `wsp:All`, rather than reporting a single gap. |
| `sp:BootstrapPolicy` | The policy governing the handshake messages themselves, so it is only reachable once the handshake is. Nothing to map, and nothing to read for the ordinary exchange: do not mine it for assertions to apply to your own messages. |
| `sp:Trust13` / `sp:Trust10` | WS-Trust negotiation with an STS, not something this package performs. |

### Verifying an endorsement the peer sends back

A policy carrying `sp:EndorsingSupportingTokens` describes both directions, so a peer that mirrors it endorses
its own responses. Every `ds:Signature` in the header has to verify, and beyond that the inbound rule is about
**how many parties** the header carries: one, and an endorsement is exempt from that count only where there is
no identity to hold it against.

| The response carries | Inbound |
|---|---|
| A MAC over the body, endorsed by a certificate. The symmetric-binding shape | Exempt unconditionally, because a MAC names no party. Hand `VerifySignature` both the trust store and `useEstablishedKey: true`, since it must resolve each signature by its own `ds:KeyInfo`. |
| A certificate signature endorsed by **the same** certificate. The ordinary asymmetric shape | Accepted: one party. Nothing to configure. |
| A certificate signature endorsed by a **different** certificate | Refused as two parties, however well each signature verifies. |
| One signature covering no other signature | Not an endorsement at all, and counted like any other signature |

The third row is the one to raise while you still have the peer's attention. A deployment that deliberately
signs with one identity and endorses with another is representable in the policy, since an endorsing supporting
token is a distinct token assertion, but it is not what a client with one keystore alias does and it is not what
this package will accept on the way in. Ask which certificate their endorsement uses before assuming the
response will verify, because the fault will not tell you.

**The parts an endorsement covered are never yours to require.** Its own coverage is not reported whoever keyed
it, so a `signed:` list naming something only the endorsement covered refuses every response. Require what the
sending party signed.

### An endorsing token under a transport binding

`sp:EndorsingSupportingTokens` beside an `sp:TransportBinding` is a real and tested configuration, not a
contradiction to flag. It is what CXF's own interop tests use. There is no message signature to endorse there,
so the specification points the endorsement at the `wsu:Timestamp` instead, and the mapping is one ordinary
`Signature` block over it:

```php
new WsseMiddleware($profile, outbound: [
    new Outbound\Timestamp(),                          // sp:IncludeTimestamp
    (new Outbound\Signature(new Signing\Asymmetric($clientCertificate)))
        ->withParts([Part::timestamp()]),              // sp:EndorsingSupportingTokens
]);
```

No `Part::primarySignature()`, and no `Encryption` block: a transport binding encrypts nothing at the message
level. Inbound, `Part::primarySignature()` is not a requirement you can state at all, and neither is anything an
endorsement alone covered. The timestamp is the whole of what this signature proves, which is worth saying out loud in the draft,
because it is a much weaker claim than the same assertion makes under a message-level binding. Requiring
`sp:IncludeTimestamp` alongside it is therefore not decoration: without a timestamp the endorsing token would
have nothing to sign.


`sp:IncludeToken` says whether the token travels with the message:

| Value | Meaning | Ours |
|---|---|---|
| `.../IncludeToken/Never` | The token is not sent; the peer resolves it from a reference | A key reference that carries no token: SKI, Issuer/Serial or Thumbprint, per the reference assertions below |
| `.../IncludeToken/AlwaysToRecipient` | Sent on every message to the recipient | `KeyRef::BinarySecurityToken`, the embedded token. With a nested `sp:Require*Reference` this conflicts; see Sending the token and referencing it inline below |
| `.../IncludeToken/Once` | Sent once per exchange | Treated as `AlwaysToRecipient`, since this package has no cross-message state. Note it. |
| `.../IncludeToken/AlwaysToInitiator` | The recipient sends its token to you | An inbound concern; nothing to configure outbound |

### Sending the token and referencing it inline

`sp:IncludeToken/AlwaysToRecipient` on a token that also carries `sp:RequireThumbprintReference` (or a key
identifier or issuer/serial one) asks for two things at once: the certificate on the wire, and a reference that
derives from the certificate and embeds nothing. It is the shape a WCF `CustomBinding` writes for an endorsing
X.509 token, so you will meet it. One `KeyRef` cannot say both: `BinarySecurityToken` embeds the token and
points at it by `wsu:Id`, and every other case embeds none.

Satisfy both by keeping the reference the assertion names and putting the token there yourself:

```php
new WsseMiddleware($profile, outbound: [
    new Outbound\Timestamp(),
    new Outbound\BinarySecurityToken($clientCertificate->publicCertificate()),
    // ...
    (new Outbound\Signature(new Signing\Asymmetric($clientCertificate, KeyRef::Thumbprint)))
        ->withParts([Part::primarySignature()]),
]);
```

**The block takes a `Certificate`, not the `ClientCertificate` you sign with**: `publicCertificate()` is the
conversion, and passing the bundle is a type error rather than a runtime surprise.

Raise it either way rather than resolving it silently. The alternative reading is that the peer wants a direct
reference and the `sp:Require*Reference` is boilerplate, which is `KeyRef::BinarySecurityToken` and no separate
block. Ask which they enforce.

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
| `sp:Header Namespace="urn:y"` with no `Name` | Every header in that namespace. No direct equivalent: `Part::soapHeaders()` covers all SOAP headers except the Security header, which is usually wider. Say so if you use it. Where the namespace is an addressing one, `WsaMiddleware` has to be listed **before** `WsseMiddleware` or this part expands to nothing and the headers travel unsigned; see [the shared rules](../../../references/wsse-import-rules.md). |
| An empty `sp:SignedParts` / `sp:EncryptedParts` | Nothing is required by that assertion; do not invent parts |
| `sp:SignedElements` / `sp:EncryptedElements` with `sp:XPath` | `Part::path(...)` when the expression is a chain of single elements from the document element down, `Part::element()` when a qualified name anywhere will do. Anything else is unmapped: ask which element is meant. |
| `sp:ContentEncryptedElements` with `sp:XPath` | The same locator, encrypting the element's **content** rather than replacing the element: `Part::element(...)->withEncryptionMode(EncryptionMode::Content)`. The mode is the whole difference from `sp:EncryptedElements`, and it is not the default for anything but `Part::body()`, so it has to be written. The enum is `Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptionMode`, one namespace deeper than the rest of `XmlSecurity`. |
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

## Vendor extensions inside the policy

A policy is an extensibility point, and stacks put their own elements in one. They are not security assertions
and none of them belongs in the mapping table, but they carry information you need.

| Element | What to do with it |
|---|---|
| `sc:KeyStore` / `sc:TrustStore` (Metro/WSIT, `.../xmlsoap/ws/2006/05/security/policy` or a WSIT namespace) | Names a JKS keystore, an alias and, in the clear, a `storepass`. Read the `alias` and `peeralias` to learn which certificate is meant, and stop there. **JKS is not parsed here**: convert with `keytool` and `openssl pkcs12 -nokeys`, and build a `TrustStore` with `TrustStore::fromPem`. Never copy the `storepass` into the output. |
| `wsoma:OptimizedMimeSerialization` | MTOM, which changes the inbound list; see the section above. |
| `wsaw:UsingAddressing`, `wsam:Addressing`, `wsap:UsingAddressing` | WS-Addressing, not security. `new WsaMiddleware()` beside this one, and the addressing headers become candidates for `sp:Header` parts. Presence is all a WSDL states here, so the defaults are the mapping and there is nothing to configure; a `wsam:Addressing` with a nested `wsam:NonAnonymousResponses` is the exception, and see [the shared rules](../../../references/wsse-import-rules.md) for why to raise that one. |
| `wsp:Optional="true"` on any assertion | Two alternatives written as one. Say which way you read it; the safe reading is to satisfy the assertion, since a peer that ignores it accepts a message carrying the protection anyway. |

Anything else vendor-specific goes on the unmapped list as a question. Do not guess at a mapping from an
element's name.

## Symmetric bindings

An `sp:SymmetricBinding` keys the signature and the encryption off one symmetric key. The mapping is expressed by
**passing one key-source object to both blocks**; nothing says "share".

| Assertion | Ours |
|---|---|
| `sp:ProtectionToken` with `sp:X509Token` | `new Keys\GeneratedSessionKey($recipientCertificate, EncKeyRef::Thumbprint)` (or whichever `EncKeyRef` the nested `sp:Require*Reference` names), plus the suite's `keyTransportAlgorithm:`. A fresh session key per exchange, carried in an `xenc:EncryptedKey`. |
| `sp:ProtectionToken` naming a key agreed out of band | `new Keys\PreSharedSessionKey($secret, $identifier, $valueType)`. Ask where the secret and the agreed identifier come from; neither is in the policy. With the WSS 1.1 `EncryptedKeySHA1` value type, which is what a WSS4J or CXF peer wants, leave the fourth argument alone: that reference writes its own base64 encoding type and declaring another is refused. |
| `sp:RequireDerivedKeys` | Wrap the source in `new Keys\DerivedSessionKey($source)` **per block**, not once and shared. Each block derives a key of its own length, and two `DerivedSessionKey` objects over one `GeneratedSessionKey` are the two `wsc:DerivedKeyToken` off one `xenc:EncryptedKey` the policy describes. |
| `sp:EncryptSignature` | Still unmapped. This package does not encrypt the `ds:Signature`. |
| `sp:AlgorithmSuite` signature token | `HmacSha1` for the binding's own signature, not `RsaSha1`. An endorsing supporting token is asymmetric and keeps `RsaSha1`, so one suite pins two different signature methods in the same message. See the AlgorithmSuite table. |
| `sp:AlgorithmSuite` key wrap | On the `GeneratedSessionKey`, as `keyTransportAlgorithm:`, not on the `Encryption` block: how the session key reaches the recipient is the key source's business. An `Rsa15` suite needs `KeyTransportAlgorithm::rsa1_5()` there, because the default is RSA-OAEP and nothing else states it. |

The signature block takes the source through a `Signing\Symmetric`:

```php
$protection = new Keys\GeneratedSessionKey(
    $recipientCertificate,
    EncKeyRef::Thumbprint,                                  // sp:RequireThumbprintReference
    keyTransportAlgorithm: KeyTransportAlgorithm::rsa1_5(), // the Rsa15 in sp:Basic128Rsa15
);

new WsseMiddleware($profile, outbound: [
    new Outbound\Timestamp(),
    (new Outbound\Signature(new Signing\Symmetric(new Keys\DerivedSessionKey($protection))))
        ->withSignatureMethod(SignatureMethod::HMAC_SHA1)   // sp:Basic128Rsa15 pins this
        ->withDigestMethod(DigestMethod::SHA1)              // and this
        ->withParts([Part::body(), Part::timestamp()]),
    (new Outbound\Encryption(new Keys\DerivedSessionKey($protection)))
        ->withDataEncryptionMethod(DataEncryptionMethod::AES128_CBC)
        ->withParts([Part::body()]),
    (new Outbound\Signature(new Signing\Asymmetric($clientCertificate, KeyRef::Thumbprint)))
        ->withSignatureMethod(SignatureMethod::RSA_SHA1)    // the same suite, asymmetric token
        ->withDigestMethod(DigestMethod::SHA1)
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

### The inbound direction is not free

A response to a symmetric-binding request carries no key of its own: each element names the key the request
conveyed. Reading it back is a configuration you state, and **the blocks will not assume it**:

```php
new WsseMiddleware($profile, outbound: [/* ... */], inbound: [
    new Inbound\Decrypt(useEstablishedKey: true),
    new Inbound\VerifySignature(useEstablishedKey: true, signed: [Part::body(), Part::timestamp()]),
    new Inbound\ValidateTimestamp(),
]);
```

`useEstablishedKey` is off by default and off means off: a `VerifySignature` given only a trust store refuses a
MAC keyed by an established key rather than accepting one it was never configured for. So an import that maps a
symmetric binding and writes the ordinary certificate-shaped inbound list **refuses every response**, and the
fault says nothing about why. This is the single easiest way to get a symmetric import wrong.

Add the trust store as well when a certificate may also sign, which is exactly the case when the policy carries
an endorsing supporting token that the peer mirrors on its responses:

```php
new Inbound\VerifySignature($trustStore, signed: [Part::body()], useEstablishedKey: true),
```

A `PreSharedSessionKey` is the other case, and it needs no flag: handing the secret over turns the same reading
on by itself, because it registers into the same place. Pass it with
`new Inbound\Decrypt(preSharedKey: $secret)` and `new Inbound\VerifySignature($trustStore, $secret)`, because
no outbound direction established it.
