# The SoapUI project WS-Security format

SoapUI and ReadyAPI store WS-Security in the project file, under the `http://eviware.com/soapui/config`
namespace (conventionally the `con:` prefix). Everything lives in one `<con:wssContainer>` element.

## Shape

A real one, from a published Axis2 interop project, reformatted (SoapUI writes the whole container on one
line):

```xml
<con:wssContainer>
  <con:crypto>
    <con:source>C:/Keystores/client_keystore.jks</con:source>
    <con:password>clientkeystorepassword</con:password>
    <con:type>KEYSTORE</con:type>
    <con:defaultAlias>client</con:defaultAlias>
    <con:aliasPassword>clientkeypassword</con:aliasPassword>
  </con:crypto>
  <con:crypto>
    <con:source>C:/Keystores/client_truststore.jks</con:source>
    <con:password>clienttruststorepassword</con:password>
    <con:type>TRUSTSTORE</con:type>
  </con:crypto>
  <con:incoming>
    <con:name>Dec+TS+Sign</con:name>
    <con:decryptCrypto>client_keystore.jks</con:decryptCrypto>
    <con:signatureCrypto>client_truststore.jks</con:signatureCrypto>
    <con:decryptPassword>clientkeypassword</con:decryptPassword>
  </con:incoming>
  <con:outgoing>
    <con:name>Enc+TS+Sign</con:name>
    <con:entry type="Encryption" username="server">
      <con:configuration>
        <crypto>client_keystore.jks</crypto>
        <keyIdentifierType>2</keyIdentifierType>
        <symmetricEncAlgorithm/>
        <encKeyTransport/>
        <encryptSymmetricKey>true</encryptSymmetricKey>
      </con:configuration>
    </con:entry>
    <con:entry type="Timestamp">
      <con:configuration>
        <timeToLive>500</timeToLive>
        <strictTimestamp>true</strictTimestamp>
      </con:configuration>
    </con:entry>
    <con:entry type="Signature" username="client" password="clientkeypassword">
      <con:configuration>
        <crypto>client_keystore.jks</crypto>
        <keyIdentifierType>2</keyIdentifierType>
        <signatureAlgorithm/>
        <useSingleCert>false</useSingleCert>
        <digestAlgorithm/>
        <signaturePart><![CDATA[<xml-fragment>
  <con:entry key="id" value=""/>
  <con:entry key="name" value="Body"/>
  <con:entry key="enc" value="Element"/>
  <con:entry key="namespace" value="http://www.w3.org/2003/05/soap-envelope"/>
</xml-fragment>]]></signaturePart>
      </con:configuration>
    </con:entry>
  </con:outgoing>
</con:wssContainer>
```

Points that are easy to get wrong:

- The element is `<con:outgoing>`. The name `outgoingWss` appears only as an **attribute on a request**
  (`outgoingWss="Enc+TS+Sign"`), selecting which configuration by its `<con:name>`. A project routinely holds
  several configurations of which one request references one, so read the request before you read the container:
  mapping the wrong `<con:outgoing>` is the easiest way to import a configuration nobody uses.
- Children of `<con:configuration>` are unprefixed and lower camel case, unlike their `con:` parents.
- **An empty element is not a value.** `<signatureAlgorithm/>`, `<encKeyTransport/>` and friends mean "unset,
  take WSS4J's default", and they are written on every entry whether or not anything was chosen. Read them as
  absent, and do not map an empty one onto an algorithm.
- **Entries name a `<con:crypto>` by the bare filename of its `<con:source>`**, not by the path and not by an
  id. `<crypto>client_keystore.jks</crypto>` resolves against `C:/Keystores/client_keystore.jks`. Two
  keystores with the same basename in different directories are indistinguishable here: raise it rather than
  guessing.
- `<con:crypto type>` is `KEYSTORE` for signing and encryption keys, `TRUSTSTORE` for verification anchors.
- `<con:defaultAlias>` and `<con:aliasPassword>` on a `<con:crypto>` name the key inside it, and an entry's
  own `username` attribute overrides the alias. The alias is what you need to pick the right key out after
  converting the keystore.
- Passwords are stored as plaintext, or as an encrypted project value. Either way they do not go into output.

## The incoming side

`<con:incoming>` blocks are the `inbound` list, and they carry no entries: the two crypto references are the
whole configuration, and each one's presence is what turns a block on.

| SoapUI | Ours |
|---|---|
| `<con:decryptCrypto>` naming a KEYSTORE, plus `<con:decryptPassword>` | `new Inbound\Decrypt($privateKey)`, the key being the one that keystore holds |
| `<con:decryptCrypto xsi:nil="true"/>` or the element absent | No `Decrypt` block. The response is not encrypted. |
| `<con:signatureCrypto>` naming a TRUSTSTORE | `new Inbound\VerifySignature($trustStore, signed: [...])` |
| `<con:signatureCrypto>` absent | No `VerifySignature` block, which means nothing about the response is checked. Worth raising: it is usually an oversight in the project rather than a peer that signs nothing. |
| A `<con:incoming>` naming a Timestamp anywhere | Nothing. SoapUI has no inbound timestamp option, so `Inbound\ValidateTimestamp` is yours to add whenever the peer sends one, and the project cannot tell you that it does. |

**The order of the inbound list is not in the file.** SoapUI applies its own fixed order and the project says
nothing about whether the peer signed before encrypting. Default to `Decrypt`, `VerifySignature`,
`ValidateTimestamp`, and say that you assumed sign-then-encrypt.

**`signed:` is not in the file either.** The Parts table belongs to the outgoing entries; nothing here says
what the response must cover. `signed:` defaults to the body alone, so name what you actually depend on and say
that it came from you rather than from the project.

## Container and configuration level

| SoapUI | Ours |
|---|---|
| `<con:outgoing mustUnderstand="true">` | `new SecurityProfile(mustUnderstand: true)`, which is already the default |
| `<con:outgoing actor="...">` or the Actor field | `new SecurityProfile(actorOrRole: '...')` |
| `<con:crypto type="KEYSTORE">` used by a Signature entry | `ClientCertificate::fromPkcs12()` or `::fromFile()`, see [Key stores](../../../../docs/key-stores.md) |
| `<con:crypto type="KEYSTORE">` used by an Encryption entry | `Certificate::fromFile()` for the recipient's public certificate |
| `<con:crypto type="TRUSTSTORE">` | `TrustStore::fromPem(Pem::fromFile(...))`, see [Key stores](../../../../docs/key-stores.md) and [Trust](../../../../docs/trust.md) |
| A `.jks` or `.jceks` source | Needs converting first, see [Converting a Java keystore](#converting-a-java-keystore) |
| A `.p12` or `.pfx` source | Usable directly via `Pkcs12Bundle` |

## Converting a Java keystore

A `.jks` / `.jceks` is not readable here. Run the conversion yourself rather than only telling the user to. The
commands are in [converting a Java keystore](../../../../docs/key-stores.md#converting-a-java-keystore); follow
them there so this file stays the mapping reference and does not drift from the docs.

What this skill has to get right:

- Ask for the keystore password and have the user export it as `KEYSTORE_PASSWORD`. Never put it on a command
  line, in a file you write, or in your output.
- `keytool -list` tells you the shape. A `<con:crypto type="KEYSTORE">` source is a signing identity: one command,
  loads as a PKCS#12. A `<con:crypto type="TRUSTSTORE">` source is anchors: two commands, because the converted
  PKCS#12 holds no private key, so it loads as a PEM bundle.
- Emit `TrustStore::fromPem(Pem::fromFile('anchors.pem'))` for a truststore, never `TrustStore::fromPkcs12()`,
  which skips the first certificate as an end-entity leaf and so silently drops an anchor. Confirm the anchor
  count matches the `trustedCertEntry` count you listed.
- If `keytool` is unavailable, say so and hand over the commands.

## Entry types

### `type="Timestamp"`

| Field | Ours |
|---|---|
| `timeToLive` | `new SecurityProfile(timestampTtl: N)`, same units. SoapUI passes the value straight to WSS4J's `WSSecTimestamp::setTimeToLive`, which takes **seconds**, so `10000` is a little under three hours rather than ten seconds. A generous value like that is usually a test convenience, not the peer's requirement: the default here is 300, and raising it widens the replay window. Ask before copying it across. |
| `strictTimestamp` / Millisecond Precision | No setting. This package emits a fixed timestamp format. |
| presence of the entry | `new Outbound\Timestamp()` |

### `type="Username"`

| Field | Ours |
|---|---|
| `username`, `password` attributes on `<con:entry>` | `new Outbound\Username($username, $password)` |
| `passwordType` = `PasswordText` | The default, so no extra call |
| `passwordType` = `PasswordDigest` | `->withDigest(true)` |
| `passwordType` empty or `None` | `new Outbound\Username($username)`, a username-only token |
| `addNonce`, `addCreated` | No settings. Both are emitted automatically when the password is digested, because the digest is computed over them. With `PasswordText` this package does not emit them: if the peer requires a nonce alongside a plaintext password, that is an unmapped item to raise. |

### `type="Signature"`

| Field | Ours |
|---|---|
| `crypto` | The keystore holding your signing identity, as a `ClientCertificate` |
| `username` / Alias, `password` | The key alias and its passphrase inside that keystore |
| `keyIdentifierType` | See the table below |
| `signatureAlgorithm` | `SignatureMethod`, via `withSignatureMethod()` or the profile |
| `signatureCanonicalization` | `SignatureCanonicalization` |
| `digestAlgorithm` | `DigestMethod` |
| `useSingleCert` | **Read it only when `keyIdentifierType` is `1`.** See below: with any other key reference it is inert. |
| `customTokenId` plus `customTokenValueType` | Only live when `keyIdentifierType` is `12`: `withKeyIdentifier()` on the `Signature` block, built from the id and the `ValueType` the two fields name. Both empty alongside a `12` is a project that will not sign, so raise it. |
| `prependSignature` | No setting. Node order in the Security header is fixed here. |
| Parts table entries | See Parts below |
| No entry at all | No `Signature` block |

`keyIdentifierType` is stored as an Apache WSS4J `WSConstants` integer, not as the label the UI shows:

| Value | WSS4J name | Ours |
|---|---|---|
| `1` | `BST_DIRECT_REFERENCE` | `KeyRef::BinarySecurityToken` |
| `2` | `ISSUER_SERIAL` | `KeyRef::IssuerSerial` |
| `3` | `X509_KEY_IDENTIFIER` | Unmapped. This puts the whole certificate in a `wsse:KeyIdentifier`, which this package does not emit. |
| `4` | `SKI_KEY_IDENTIFIER` | `KeyRef::SubjectKeyIdentifier` |
| `5` | `EMBEDDED_KEYNAME` | Encryption only. A key from the keystore rather than a wrapped one; see `embeddedKeyName` below. |
| `6` | `EMBED_SECURITY_TOKEN_REF` | Encryption only. Unmapped, an embedded token reference. |
| `8` | `THUMBPRINT_IDENTIFIER` | `KeyRef::Thumbprint` |
| `12` | `CUSTOM_KEY_IDENTIFIER` | Signature only. `withKeyIdentifier()` built from `customTokenId` and `customTokenValueType`; see below. |

**A missing element, and an explicit `0`, both mean `ISSUER_SERIAL`.** Not "unset", and not a direct reference:
SoapUI reads the field with `ISSUER_SERIAL` as its default and maps `0` onto the same value deliberately, for
backward compatibility. So a Signature or Encryption entry that says nothing about its key reference still
needs `KeyRef::IssuerSerial` written, because that is not this package's default. Getting this backwards
produces a `wsse:BinarySecurityToken` where the peer expects an issuer and serial.

Which values each entry offers differs, so a value outside its own set was not set through the UI and is worth
questioning: a Signature entry offers `1, 2, 3, 4, 8, 12` and an Encryption entry offers `1, 2, 3, 4, 5, 6, 8`.

Confirmed against WSS4J 1.6.x `WSConstants`, SoapUI's own `SignatureEntry` and `EncryptionEntry` combo boxes
and `WssEntryBase::readKeyIdentifierType`, and seven real project files (Axis2, Metro and CXF interop
projects), every one of which carries `2`.

#### `useSingleCert` and the key reference are not independent

`useSingleCert` = `false` means "advertise the whole certification path", and a path can only travel inside an
embedded token. So it means something only when `keyIdentifierType` is `1`, the direct reference. With `2`, `4`,
`8` or `12` there is no token in the message at all, and both WSS4J and this package have nowhere to put a
chain.

That matters because **SoapUI's two defaults collide**: `keyIdentifierType` resolves to `2` when unset and
`useSingleCert` defaults to `false`, so the combination is what real projects overwhelmingly carry. Mapping it
literally throws:

```
A certificate path needs KeyRef::BinarySecurityToken to carry it.
```

`Signing\Asymmetric` refuses `path:` alongside any other `KeyRef` rather than advertising less than you asked
for, so this is a runtime failure and not something a typecheck will show you.

| The project says | Ours |
|---|---|
| `keyIdentifierType` `1`, `useSingleCert` false or absent | `new Signing\Asymmetric($clientCertificate, KeyRef::BinarySecurityToken, path: $chain)` |
| `keyIdentifierType` `1`, `useSingleCert` true | `new Signing\Asymmetric($clientCertificate)`, the default |
| Any other `keyIdentifierType`, whatever `useSingleCert` says | `new Signing\Asymmetric($clientCertificate, KeyRef::IssuerSerial)` and **no** `path:`. Say in the output that you dropped `useSingleCert`, and why. |

If the peer genuinely needs the intermediates on the wire alongside a non-token reference, that is the same
conflict the WS-SecurityPolicy import meets: add `Outbound\BinarySecurityToken::forCertificatePath($chain)` as
its own block and keep the inline reference. Raise it rather than doing it silently, because the project does
not ask for it.

### `type="Encryption"`

| Field | Ours |
|---|---|
| `crypto` plus Alias | The recipient's certificate, wrapped as `new Keys\GeneratedSessionKey($recipientCertificate)` and passed to the block |
| `keyIdentifierType` | The same table, read as `EncKeyRef` instead of `KeyRef`, and passed to the `GeneratedSessionKey` rather than to the block |
| `encryptSymmetricKey` = true, **and an absent element** | The ordinary case: a fresh session key wrapped under the recipient's certificate, which is what `Keys\GeneratedSessionKey` writes. SoapUI labels it "Create Encrypted Key" and defaults it to `true`. |
| `encryptSymmetricKey` = false | No `xenc:EncryptedKey` is written at all, so the two sides must already share the key. Not something `GeneratedSessionKey` can express: ask what the shared secret and its agreed identifier are, and map it to `Keys\PreSharedSessionKey`. |
| `symmetricEncAlgorithm` | `DataEncryptionMethod` |
| `keyEncryptionAlgorithm` | A `KeyTransportAlgorithm` passed as `keyTransportAlgorithm:` to the `GeneratedSessionKey`, which is what wraps the key. A bare `KeyEncryptionMethod` is not accepted there: it sets a profile-wide default on `CryptoPolicy` and nothing else, and `Encryption` has no `withKeyEncryptionMethod()` to override it per block. Use the named constructors (`rsa1_5()`, `legacyMgf1p()`, `oaepSha256()`), or `KeyTransportAlgorithm::fromMethod()` for a pairing they do not cover. |
| `embeddedKeyName`, `embeddedKeyPassword` | A key from the keystore rather than a freshly wrapped one: `new Keys\PreSharedSessionKey($secret, $identifier, $valueType)`. SoapUI names the key by its keystore alias, which is **not** the identifier a peer references it by on the wire, so ask what the two sides agreed on; neither the alias nor the password is it. The secret itself has to be exported from the keystore, which this package cannot read. |
| Parts table entries | See Parts below |

### `type="SAML"` (XML form)

The assertion XML maps to `new Outbound\SamlAssertion($xml, $version)`. The form-based SAML entry, which mints
and signs an assertion inside SoapUI, has no counterpart: this package imports an assertion, it does not issue
one. Ask where the real assertion comes from.

## WS-Addressing: `<con:wsaConfig>`

Not WS-Security, and not part of `WssContainer`: it sits on the request, and falls back to the operation and
then the interface, so read it from the same request whose `outgoingWss` you followed. It maps onto
`WsaMiddleware`, a separate middleware; see [the shared rules](../../../references/wsse-import-rules.md) for the
four facts that hold whatever format you read addressing from.

```xml
<con:wsaConfig mustUnderstand="NONE" version="200508" action="urn:getAdminToken" generateMessageId="true"/>
```

| Attribute | Ours |
|---|---|
| `version="200508"` | `WsaNamespace::W3c200508`, already the default |
| `version="200408"` | `WsaNamespace::Submission200408` |
| `addDefaultAction="true"` | The default: `action: null` takes it from the request's `SOAPAction` |
| `addDefaultTo="true"` | The default: `to: null` uses the request URI |
| `action="..."` | `new WsaOptions(action: '...')`. Check it looks like a URI first: projects here carry bare local names such as `getAdminToken`, which go on the wire verbatim and are probably not what the service matches on. Raise one that does. |
| `addDefaultTo="false"` with no `to` | Omitting `wsa:To` altogether, which is not representable: `to: null` derives one rather than dropping it. Raise it. |
| `replyTo` = the version's `/anonymous` URI | `replyTo: null`, the default. The commonest value in real projects. |
| `replyTo` = the version's `/none` URI | Discard the reply. Not usable from a request/response client, and not representable. Raise it. |
| `replyTo` / `faultTo` = a real address | `new WsaOptions(replyTo: '...', faultTo: '...')`, but see the shared rules: an address needs something listening, which this client is not. |
| `from="..."` | `new WsaOptions(from: '...')` |
| `generateMessageId`, `messageID` | Unmapped either way. The id is always freshly generated and can be neither fixed nor suppressed. SoapUI's values here are usually property expansions like `${Properties#MessageID}`. |
| `relatesTo` | Unmapped, and meaningless outbound |
| `replyToRefParams`, `faultToRefParams` | Unmapped: reference parameters on the endpoint reference |
| `mustUnderstand="NONE"`, `"TRUE"`, `"FALSE"` | Unmapped. These headers carry no `mustUnderstand` here, and `SecurityProfile(mustUnderstand:)` is the Security header, not this. `NONE` is what almost every real project carries anyway. |

An empty attribute value (`from=""`, `messageID=""`) is unset, the same convention as the empty elements inside
`<con:configuration>`. A project with no `wsaConfig` at all wants no addressing, so add no middleware.

**A `${...}` value is a property expansion, not a value.** `replyTo="${#Project#publicIp}"` names a project
property defined elsewhere in the same file, and copying the literal puts `${#Project#publicIp}` on the wire.
Resolve it from the `<con:properties>` block, then reference the resolved value the way the surrounding
application does rather than hardcoding somebody's test host. This applies to any attribute in the project, not
only these.

**Which of these actually produce an argument.** Across every sample in the corpus, only four ever do:
`action`, `from`, `replyTo` and `faultTo`. Two `WsaOptions` arguments are therefore mapped from the
documentation and exercised by no file: `namespace`, because `version` is `200508` in all 97 `wsaConfig`
elements, and `to`, because nothing sets an explicit To and `addDefaultTo="false"` asks for the opposite, an
omission this package cannot express. Everything else on the element is either already the default or
unmappable, which is why a faithful import of a SoapUI project usually ends at
`new WsaMiddleware(new WsaOptions(action: '...'))`.

## Parts

Both the Signature and Encryption entries carry a Parts table, and it is not stored as a table. Each row is one
`<signaturePart>` element on a Signature entry, or one `<encryptionPart>` on an Encryption entry, holding an
escaped or CDATA-wrapped `<xml-fragment>` of key/value pairs:

```xml
<signaturePart><![CDATA[<xml-fragment>
  <con:entry key="id" value=""/>
  <con:entry key="name" value="Body"/>
  <con:entry key="enc" value="Element"/>
  <con:entry key="namespace" value="http://schemas.xmlsoap.org/soap/envelope/"/>
</xml-fragment>]]></signaturePart>
```

The four keys are `id`, `name`, `namespace` and **`enc`**, and the pairs come in no fixed order. `enc` is the
key, not `encode`, and it is written on a signature row too, where it means nothing: a signature covers the
element either way, so read `enc` only on an Encryption entry.

The fragment is sometimes CDATA and sometimes `&lt;`-escaped, in the same file, so unescape before parsing
rather than pattern-matching the raw text.

Watch the envelope namespace in the `Body` row: `http://schemas.xmlsoap.org/soap/envelope/` is SOAP 1.1 and
`http://www.w3.org/2003/05/soap-envelope` is SOAP 1.2. Either way it is `Part::body()`, but it tells you which
SOAP version the project speaks, which nothing else in the container does.

**An empty Parts table does not mean nothing is protected**, which is why so many working SoapUI projects have
one. SoapUI's own documentation says the whole message is covered; WSS4J, underneath it, defaults to the SOAP
Body. Treat it as the default part list and write no `withParts()` call, and if the peer requires headers covered
too, say that you read the empty table as Body-only and that a captured message should confirm it.

| Parts row | Ours |
|---|---|
| Name `Body`, namespace of the SOAP envelope | `Part::body()` |
| Name `Timestamp`, WS-Security utility namespace | `Part::timestamp()` |
| Name `UsernameToken`, WS-Security namespace | `Part::usernameToken()` |
| Any other name plus namespace | `Part::element($namespace, $name)`, or `Part::path(...)` when the element must sit at a fixed position |
| An `id` value | `Part::byId($id)` |
| `enc` = `Content` | The `Part::body()` default. Other parts default to `Element`, so use `->withEncryptionMode(EncryptionMode::Content)` when a row asks for Content. The enum is `Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptionMode`. |
| `enc` = `Element` | `Part::body()->withEncryptionMode(EncryptionMode::Element)` for the Body; the default for every other part |

A long Parts table listing each header individually is usually better expressed as
`Part::securityHeaderContents()` or `Part::soapHeaders()`, which resolve against the live message. Say when you
make that substitution, since it can cover more than the original list.

**The table is element-oriented and cannot express an attachment.** Its columns address XML by name, namespace
or id, and SoapUI's WS-Security UI offers no attachment option, so a project you are handed will never ask for
attachment signing or encryption. If the peer needs it, that requirement came from somewhere other than this
file: see [Attachment security](../../../../docs/attachments.md).
