# The IBM WebSphere WS-Security descriptor formats

## Which file holds what

WebSphere splits requirements from key material, across as many as five files.

| File | Holds |
|---|---|
| `ws-security.xml` (cell or server level) | Default key material for a whole cell: `trustAnchors`, `certStoreList`, `keyLocators`, `trustedIDEvaluators`, `loginMappings`. Nothing about protected parts. |
| `ibm-webservicesclient-ext.xmi` | Client requirements: `integrity`, `confidentiality`, `loginConfig`, `addCreatedTimeStamp` |
| `ibm-webservicesclient-bnd.xmi` | Client algorithms and keys: `signingInfo`, `encryptionInfo`, `keyLocators`, `trustAnchors`, `certPathSettings` |
| `ibm-webservices-ext.xmi` | The same requirements, server side |
| `ibm-webservices-bnd.xmi` | The same algorithms and keys, server side |

The more specific file wins: application binding, then server, then cell.

From WAS 7 onward a policy set replaces this: `policy.xml` is plain WS-SecurityPolicy (`sp:SignedParts`,
`sp:EncryptedParts`, `sp:AlgorithmSuite`) and `bindings.xml` holds the IBM key and token wiring. Read the policy
for what is protected and the bindings only for key material.

## Requirements

The `ext` files state what must be secured. A client descriptor looks like this:

```xml
<clientServiceConfig actorURI="myActorURI">
  <securityRequestSenderServiceConfig actor="myActorURI">
    <integrity>
      <references part="body"/>
      <references part="timestamp"/>
      <references part="securitytoken"/>
    </integrity>
    <confidentiality>
      <confidentialParts part="bodycontent"/>
    </confidentiality>
    <loginConfig authMethod="BasicAuth"/>
    <addCreatedTimeStamp flag="true" expires="PT3M"/>
  </securityRequestSenderServiceConfig>
  <securityResponseReceiverServiceConfig>
    <requiredIntegrity><references part="body"/></requiredIntegrity>
    <requiredConfidentiality><confidentialParts part="bodycontent"/></requiredConfidentiality>
    <addReceivedTimeStamp flag="true"/>
  </securityResponseReceiverServiceConfig>
</clientServiceConfig>
```

| Their setting | Ours |
|---|---|
| `addCreatedTimeStamp flag="true" expires="PT3M"` | `new Outbound\Timestamp()` plus `new SecurityProfile(timestampTtl: 180)`. The value is an ISO 8601 duration; convert to seconds. |
| `integrity` | `new Outbound\Signature(new Keys\AsymmetricSigningKey($clientCertificate))`, with `withParts()` only if the parts differ from the default |
| `confidentiality` | `new Outbound\Encryption(new Keys\GeneratedSessionKey($recipientCertificate))`, likewise |
| `loginConfig authMethod="BasicAuth"` | `new Outbound\Username($user, $password)`, which sends `PasswordText` |
| `authMethod="Signature"` | No `Username` block. The identity is the signing certificate. |
| `authMethod="IDAssertion"` or `LTPA` | Unmapped. Ask which credential is actually expected. |
| `requiredIntegrity` | `new Inbound\VerifySignature($trustStore, signed: [...])` |
| `requiredConfidentiality` | `new Inbound\Decrypt($privateKey)` |
| `addReceivedTimestamp flag="true"` | `new Inbound\ValidateTimestamp()` |
| `actorURI`, `actor`, `role` | `new SecurityProfile(actorOrRole: '...')` |

Remember the mirroring rule: on a service's own descriptor, the receiver sections drive your outbound and the
response sender sections drive your inbound.

## Part keywords

| Their keyword | Ours |
|---|---|
| `body` under integrity | `Part::body()` |
| `bodycontent` under confidentiality | `Part::body()`, which already encrypts in `EncryptionMode::Content` |
| `body` under confidentiality | `Part::body()->withEncryptionMode(EncryptionMode::Element)`. This is the one case where the keyword and our default disagree; read it twice. |
| `timestamp` | `Part::timestamp()` |
| `securitytoken` | `Part::binarySecurityToken()` |
| `usernametoken` | `Part::usernameToken()` |
| `nonce`, `created` | Unmapped. Children of the UsernameToken, not separately addressable. |
| A WAS 6 `partReference` with the `dialect-was` dialect | Read its `keyword` as one of the rows above |
| A `partReference` with an XPath dialect | `Part::path(...)` when the expression is a chain of single elements from the document element down, `Part::element()` when a qualified name anywhere will do. Anything else is unmapped: ask which element is meant. |

A long list of individually named header parts is usually better expressed as
`Part::securityHeaderContents()` or `Part::soapHeaders()`. Say when you make that substitution, since it can
cover more than the original list.

## Algorithms

The `bnd` files carry algorithm URIs:

```xml
<signingInfo>
  <signatureMethod algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <signingKey name="clientsignerkey" locatorRef="SampleClientSignerKey"/>
  <canonicalizationMethod algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
  <digestMethod algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
</signingInfo>
<encryptionInfo name="EncInfo1">
  <encryptionKey name="CN=Bob, O=IBM, C=US" locatorRef="SampleSenderEncryptionKeyLocator"/>
  <encryptionMethod algorithm="http://www.w3.org/2001/04/xmlenc#tripledes-cbc"/>
  <keyEncryptionMethod algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
</encryptionInfo>
```

| Their element | Ours |
|---|---|
| `signatureMethod/@algorithm` | `SignatureMethod`, on `signatureMethod:` and `acceptedSignatureMethods:` |
| `digestMethod/@algorithm` | `DigestMethod`, on `digestMethod:` and `acceptedDigestMethods:` |
| `canonicalizationMethod/@algorithm` | `SignatureCanonicalization`, on `canonicalization:` and `acceptedCanonicalizations:` |
| `encryptionMethod/@algorithm` | `DataEncryptionMethod`, on `dataEncryptionMethod:` and `acceptedDataEncryptionMethods:` |
| `keyEncryptionMethod/@algorithm` | `KeyEncryptionMethod`, or `KeyTransportAlgorithm` when the OAEP hashes matter |

The example above is typical, and every one of its four algorithms is refused by the default `CryptoPolicy`.
That is not a bug to work around: rule 2 of the shared rules applies to each one. Both directions need
attention, the outbound choice and the inbound allow-list, because they are separate settings.

## Key references

WAS 6 and later name the key reference in a `keyInfo` element with a `type` attribute.

| Their type | Ours |
|---|---|
| `STRREF` | `KeyRef::BinarySecurityToken`, embedding the token and pointing at it by `wsu:Id` |
| `KEYID` | `SubjectKeyIdentifier` |
| `X509ISSUER` | `IssuerSerial` |
| `THUMBPRINT` | `Thumbprint` |
| `EMB` | Unmapped, an embedded token |
| `KEYNAME` | Unmapped |

Read the type as a `KeyRef` on the signature and an `EncKeyRef` on the encryption. A JAX-RPC file with no
`keyInfo` at all usually means a direct reference, since that is WebSphere's own signing default, but confirm it
against a captured message rather than assuming.

## Trust and key material

```xml
<certPathSettings>
  <trustAnchorRef ref="SampleClientTrustAnchor"/>
  <certStoreRef ref="SampleCollectionCertStore"/>
</certPathSettings>
<trustAnchors name="SampleClientTrustAnchor">
  <keyStore storepass="{xor}PDM2OjEr" type="JKS" path="$${USER_INSTALL_ROOT}/.../dsig-sender.ks"/>
</trustAnchors>
<certStoreList>
  <collectionCertStores provider="IBMCertPath" name="SampleCollectionCertStore">
    <x509Certificates path="$${USER_INSTALL_ROOT}/.../intca2.cer"/>
  </collectionCertStores>
</certStoreList>
```

| Their setting | Ours |
|---|---|
| `trustAnchors/keyStore` | `TrustStore::fromPem(Pem::fromFile(...))`, once converted |
| `collectionCertStores/x509Certificates/@path` | Intermediates, loaded as a `Pem` bundle |
| A CRL in the cert store | `->withRevocationLists(...)`, see [Trust](../../../../docs/trust.md) |
| `signingKey` plus its `keyLocators` entry | `ClientCertificate`, see [Key stores](../../../../docs/key-stores.md) |
| `encryptionKey name="CN=..."` | `Certificate` for that recipient's public certificate |

Every keystore here is a JKS or JCEKS, which this package cannot read: it takes PEM and PKCS#12. Run the
conversion yourself rather than only telling the user to. The commands are in
[converting a Java keystore](../../../../docs/key-stores.md#converting-a-java-keystore); follow them there so
this file stays the mapping reference and does not drift from the docs.

What this skill has to get right:

- Ask the user for the keystore password and have them export it as `KEYSTORE_PASSWORD`. Never put it on a
  command line, in a file you write, or in your output.
- Check the shape first with `keytool -list`. `PrivateKeyEntry` means a signing identity, one command, loads as a
  PKCS#12 via `ClientCertificate::fromPkcs12()`. `trustedCertEntry` means anchors, two commands, loads as a PEM
  bundle.
- Emit `TrustStore::fromPem(Pem::fromFile('anchors.pem'))` for a truststore, never `TrustStore::fromPkcs12()`,
  which skips the first certificate as an end-entity leaf and silently drops an anchor. Confirm the anchor count
  matches the `trustedCertEntry` count you listed.
- If `keytool` is unavailable (no Java on the machine), say so and hand the user the commands instead.

Paths often contain WebSphere variables such as `$${USER_INSTALL_ROOT}`. They are not resolvable from outside the
cell, so treat them as names to ask about, not paths to read.

Keystore passwords appear as `{xor}` strings. The encoding is reversible, which is exactly why a decoded password
must never reach output or a commit.

## Unmapped, by design

- **JKS and JCEKS keystores, as a format.** Nothing here parses them. They are converted with `keytool` first,
  as above, and only the PEM or PKCS#12 result is loaded.
- **`keyLocators`, `tokenGenerator`, `tokenConsumer` class names.** Java plug points. Some encode behaviour with
  no client-side equivalent at all: `CertInRequestKeyLocator` means "encrypt the response under whichever key
  signed the request".
- **JAAS login configurations and callback handler classes.** Ask which credential is really sent.
- **`trustedIDEvaluators` and identity assertion.** A server-side trust decision.
- **`loginMappings`.** Server-side authentication wiring.
- **Per-port and per-operation scoping.** Ask which port this client speaks to.
- **Arbitrary XPath part references.** Ask which element is meant.
- **Attachment security.** These descriptors carry no attachment-security settings at all: the part keywords
  address the body, the timestamp and named tokens, and nothing addresses a MIME part. A peer needing it says
  so somewhere other than here, most often in a WS-SecurityPolicy: see
  [Attachment security](../../../../docs/attachments.md).
