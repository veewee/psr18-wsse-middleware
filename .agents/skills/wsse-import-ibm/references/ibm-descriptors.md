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

From WAS 7 onward a policy set replaces this, and it is a different shape rather than a tidier one. See
[Policy sets](#policy-sets-was-7-and-later) below: read `policy.xml` for what is protected and `bindings.xml`
for the keys and tokens, but neither reads the way its equivalent does anywhere else.

## Finding your configuration in the file

One `.xmi` holds every service reference the module makes, and you want one of them. The nesting is:

```xml
<com.ibm.etools.webservice.wscext:WsClientExtension ...>
  <serviceRefs serviceRefLink="service/WindupService">
    <portQnameBindings portQnameLocalNameLink="WindupServicePort">
      <clientServiceConfig> ... </clientServiceConfig>
```

and a second copy of the same nesting may sit under `<componentScopedRefs componentNameLink="SomeEJB">` for a
reference an EJB makes rather than the module. Match on `serviceRefLink` and `portQnameLocalNameLink` together:
one service with two ports carries two configurations that differ, and importing the wrong one produces a
plausible draft for a port you do not call. If you cannot tell which, list what you found and ask.

## Policy sets, WAS 7 and later

A policy set is a directory tree, not a file:

```
PolicySets/<set name>/PolicyTypes/WSSecurity/policy.xml     what is protected
PolicyTypes/WSSecurity/bindings.xml                         which keys and tokens do it
```

**Name means nothing. Read the file.** WebSphere's shipped "Username WSSecurity default" is a full
`sp:AsymmetricBinding` with `Basic128Rsa15`, signing and encrypting the body in both directions, that happens to
also carry a `sp:UsernameToken`. Someone telling you "we just use Username WSSecurity default" is describing
five blocks, not one.

### `policy.xml` is WS-SecurityPolicy with two IBM conventions on top

Do not hand it to the WS-SecurityPolicy import unread. Two things differ, and both change the answer:

**There are no alternatives.** The root `wsp:Policy` holds its assertions as direct children with no
`wsp:ExactlyOne` and no `wsp:All` anywhere. Looking for alternatives to choose between finds nothing, and there
is no choice to report.

**Direction comes from `wsu:Id`, not from an attachment point.** The parts assertions sit inside nested
`wsp:Policy` elements whose ids carry the direction as a prefix:

```xml
<wsp:Policy wsu:Id="request:app_signparts">
  <sp:SignedParts><sp:Body/></sp:SignedParts>
  ...
</wsp:Policy>
<wsp:Policy wsu:Id="response:app_signparts">
  ...
```

| `wsu:Id` | Where it lands |
|---|---|
| `request:app_signparts` / `request:app_encparts` | `withParts()` on the outbound `Signature` / `Encryption` |
| `response:app_signparts` | **`signed:` on `Inbound\VerifySignature`** |
| `response:app_encparts` | Nothing to configure; `Decrypt` decrypts what arrives marked |
| `request:token_auth` | The supporting token, request only |
| `request:bootstrap_*` / `response:bootstrap_*` | The WS-SecureConversation handshake. Ignore them: this package does not perform the handshake, and mining them for parts applies the handshake's rules to your application messages. |

An id you do not recognise is a question, not a part list. The binding assertion itself sits outside all of
these and applies both ways, as it does everywhere.

### The namespaces are older than you expect

| Prefix | Value in a shipped WAS policy set |
|---|---|
| `sp:` | `http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200512`, the committee draft between the 2005 submission and the 200702 standard |
| `wsp:` | `http://schemas.xmlsoap.org/ws/2004/09/policy`, WS-Policy 1.2, not the 1.5 `http://www.w3.org/ns/ws-policy` |
| `sp:IncludeToken` values | `.../ws-securitypolicy/200512/IncludeToken/...` |

Matching on the 200702 namespace, or on WS-Policy 1.5, finds nothing in one of these files. The assertion
vocabulary is otherwise the same, so the WS-SecurityPolicy reference's tables all apply.

### IBM writes XPath where an assertion would do

Every part IBM can express as an XPath, it does, in one canonical fully-qualified form:

```xml
<sp:SignedElements>
  <sp:XPath>/*[namespace-uri()='http://schemas.xmlsoap.org/soap/envelope/' and local-name()='Envelope']/*[...'Header']/*[...'Security']/*[...'Timestamp']</sp:XPath>
```

Three rules for reading them:

1. **Recognise the shortcuts.** That expression is `Part::timestamp()`. The `UsernameToken` one is
   `Part::usernameToken()`. Build a `Part::path()` only for an expression that is not one of the named parts.
2. **The XPaths come in SOAP 1.1 and SOAP 1.2 pairs**, one naming
   `http://schemas.xmlsoap.org/soap/envelope/` and one `http://www.w3.org/2003/05/soap-envelope`. Four
   expressions are usually two parts. Mapping them one for one produces a part list half of which can never
   match, and on the inbound side a `signed:` requirement that refuses every response.
3. **An `sp:EncryptedElements` XPath naming `ds:Signature` is `sp:EncryptSignature` in disguise**, and stays
   unmapped: this package does not encrypt the signature. Refuse it in that form too rather than writing the
   `ds:Signature` into an encrypted part list. Both shipped WS-Security policy sets do this in both directions,
   so expect it.

The same doubling shows up on header assertions: a `sp:Header Namespace=` for both
`http://schemas.xmlsoap.org/ws/2004/08/addressing` and `http://www.w3.org/2005/08/addressing` is one
requirement about addressing headers, written twice.

### The `WSAddressing` policy type

A policy set carries one `PolicyTypes/WSAddressing/policy.xml` beside its `WSSecurity` one, and it is a
different vocabulary again: WS-Addressing 1.0 Metadata, `wsam:` on
`http://www.w3.org/2007/05/addressing/metadata`. Every shipped set has one and they are all this shape:

```xml
<wsp:Policy>
  <wsp:ExactlyOne><wsp:All>
    <wsam:Addressing wsp:Optional="true">
      <wsp:Policy><wsp:ExactlyOne>
        <wsp:All/>
        <wsam:AnonymousResponses/>
        <wsam:NonAnonymousResponses/>
      </wsp:ExactlyOne></wsp:Policy>
    </wsam:Addressing>
  </wsp:All></wsp:ExactlyOne>
</wsp:Policy>
```

| Assertion | Ours |
|---|---|
| `wsam:Addressing` | `new WsaMiddleware()`, beside the `WsseMiddleware` rather than inside it |
| `wsp:Optional="true"` on it | Addressing is permitted, not required. Sending it conforms either way, so send it. |
| `wsam:AnonymousResponses` | `replyTo: null`, which is the version's anonymous URI, so nothing to write |
| `wsam:NonAnonymousResponses` | The reply goes to an address you name, which a PSR-18 client has nothing listening on. Raise it rather than setting `replyTo:` and calling it done. |
| The empty `<wsp:All/>` alternative | Either response style is accepted, so the default is fine |

Unlike the `WSSecurity` policy this one does use `wsp:ExactlyOne`, and it is nested: the outer one has a single
alternative and the inner one offers three. Note also `xmlns:wsp="http://www.w3.org/ns/ws-policy"` here, WS-Policy
1.5, where the `WSSecurity` policy in the same set uses 1.2. One policy set, two policy namespaces.

See [the shared rules](../../references/wsse-import-rules.md) for what holds about addressing whatever format
it came from.

### `bindings.xml`

```xml
<securityBindings>
  <securityBinding name="application">
    <securityOutboundBindingConfig>
      <signingInfo order="1" name="asymmetric-signingInfoResponse"> ... </signingInfo>
      <keyInfo type="STRREF" name="gen_signkeyinfo"><tokenReference reference="gen_signx509token"/></keyInfo>
      <tokenGenerator name="gen_signx509token" ...> ... </tokenGenerator>
    </securityOutboundBindingConfig>
    <securityInboundBindingConfig> ... </securityInboundBindingConfig>
```

The file is a graph, not a list: a `signingInfo` names a `keyInfo` by `reference`, which names a
`tokenGenerator` by `reference`, which carries the keystore. Follow the chain rather than reading the
`tokenGenerator` elements in order, because a file holds more of them than the policy uses.

| In the bindings | Ours |
|---|---|
| `securityOutboundBindingConfig` | The `outbound` list **of whoever owns this file**. On a service's own bindings its outbound is the response, which the `...Response` suffix in the `name` confirms. Mirror it. |
| `securityInboundBindingConfig` | Likewise the other direction, `...Request` in the names |
| `order="N"` on `signingInfo` / `encryptionInfo` | The block order, and the only statement of it. `signingInfo` before `encryptionInfo` is sign-then-encrypt; the reverse means reversing our block order and the inbound list with it. |
| Several `signingInfo` / `encryptionInfo` in one config | Alternatives, conventionally named `asymmetric-*` and `symmetric-*`. Which one applies is decided by the token the policy asks for, so read the policy first and take the matching pair. |
| `keyEncryptionKeyInfo` on an `encryptionInfo` | A session key wrapped under a certificate: `Keys\GeneratedSessionKey` |
| `dataEncryptionKeyInfo` inside `encryptionPartReference` | The data keyed directly off an established or shared secret, with no wrapped key: `Keys\PreSharedSessionKey`, or the SecureConversation case below |
| `<transform algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>` | Exclusive C14N, already the default |
| `keyInfo type=` | The same `STRREF` / `KEYID` / `X509ISSUER` / `THUMBPRINT` table as the `.xmi` bindings |

A `tokenGenerator` or `tokenConsumer` is identified by its `valueType localName`:

| `valueType localName` | Ours |
|---|---|
| `...wss-x509-token-profile-1.0#X509v3` | An X.509 certificate: the signing identity, or the recipient's certificate on an encryption chain |
| `...wss-username-token-profile-1.0#UsernameToken` | `new Outbound\Username(...)` |
| `LTPA`, `LTPA_PROPAGATION` (uri `http://www.ibm.com/websphere/appserver/tokentype...`) | Unmapped and unclosable: a WebSphere-minted proprietary binary token. A port requiring one cannot be called from outside the cell as configured. |
| `http://schemas.xmlsoap.org/ws/2005/02/sc/sct` | A WS-SecureConversation token, obtained by an RST/RSTR handshake this package does not perform. If the policy's protection token is this, the whole set is unimplementable; say so rather than reporting one gap. |

Two callback-handler properties are worth reading, because they map onto settings that are off by default here:

| Property on a `callbackHandler` | Ours |
|---|---|
| `com.ibm.wsspi.wssecurity.token.username.addNonce` = true | `->withNonce(true)` on `Outbound\Username` |
| `com.ibm.wsspi.wssecurity.token.username.addTimestamp` = true | `->withCreated(true)` |

Key material sits on the `callbackHandler`, and it is the JKS problem again:

```xml
<callbackHandler classname="com.ibm.websphere.wssecurity.callbackhandler.X509GenerateCallbackHandler">
  <key alias="soapprovider" keypass="{xor}..." name="CN=SOAPProvider, OU=TRL, O=IBM, ST=Kanagawa, C=JP"/>
  <keyStore storepass="{xor}..." path="${USER_INSTALL_ROOT}/etc/ws-security/samples/dsig-receiver.ks" type="JKS"/>
</callbackHandler>
```

`type` is `JKS` or `JCEKS`, and both need the `keytool` conversion below. `${USER_INSTALL_ROOT}` and friends are
WebSphere variables, so a path is not a path until someone resolves them: ask rather than guessing at the
profile root. The `alias` is what you need to pick the right key out after converting, and the `name` is the
subject DN, which is a useful cross-check that you converted the right entry.

**A file from a collector dump has its passwords masked** to a literal `{xor}********` rather than a real
encoded value. That is not a decodable secret and not a bug in the dump. Either way no `{xor}` string, masked or
not, goes into your output.


## Requirements

The `ext` files state what must be secured.

**Two generations of element name, and a file uses one or the other.** Older descriptors say
`securityRequestSenderServiceConfig` and `securityResponseReceiverServiceConfig`; the ones written from WAS
5.0.2 onward say `securityRequestGeneratorServiceConfig` and `securityResponseConsumerServiceConfig`. Grep for
both before concluding a descriptor carries no security: the outer nesting is identical, so the wrong spelling
finds nothing and looks like an unsecured port. The tables below apply to either spelling.

A client descriptor looks like this:

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
| `integrity` | `new Outbound\Signature(new Signing\Asymmetric($clientCertificate))`, with `withParts()` only if the parts differ from the default |
| `confidentiality` | `new Outbound\Encryption(new Keys\GeneratedSessionKey($recipientCertificate))`, likewise |
| `loginConfig authMethod="BasicAuth"` | `new Outbound\Username($user, $password)`, which sends `PasswordText` |
| `authMethod="Signature"` | No `Username` block. The identity is the signing certificate. |
| `authMethod="IDAssertion"` or `LTPA` | Unmapped. Ask which credential is actually expected. |
| `requiredIntegrity` | `new Inbound\VerifySignature($trustStore, signed: [...])` |
| `requiredConfidentiality` | `new Inbound\Decrypt($privateKey)` |
| `addReceivedTimestamp flag="true"` | `new Inbound\ValidateTimestamp()` |
| `actorURI`, `actor`, `role` | `new SecurityProfile(actorOrRole: '...')` |
| An **empty** `securityResponseConsumerServiceConfig` or `securityResponseReceiverServiceConfig` | Nothing is required of the response, so no inbound blocks. Present-but-empty is a real configuration and not a truncated file. Say that the response goes unchecked, because it is more often an oversight in the descriptor than a peer that protects nothing. |
| A `securityToken` element with `localName` ending `#UsernameToken` | `new Outbound\Username($user, $password)`. The `name` attribute is the token's name in WebSphere's own configuration, not the username: the credential comes from the bindings or from a callback handler, so ask for it. |
| A `securityToken` with `localName="LTPA"` and the `websphere/appserver/tokentype` uri | Unmapped, and not a gap you can close: an LTPA token is a WebSphere-proprietary binary token minted by the cell's own security runtime, which this package cannot obtain or produce. Say so plainly, since it is common in WebSphere-to-WebSphere calls and it means this port cannot be called from outside the cell as configured. |
| A `securityToken` with `localName` ending `#X509v3` | The signing identity, or `new Outbound\BinarySecurityToken($certificate)` where nothing signs |

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
