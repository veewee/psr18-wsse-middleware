# The SoapUI project WS-Security format

SoapUI and ReadyAPI store WS-Security in the project file, under the `http://eviware.com/soapui/config`
namespace (conventionally the `con:` prefix). Everything lives in one `<con:wssContainer>` element.

## Shape

```xml
<con:wssContainer>
  <con:crypto>
    <con:source>/path/to/clientKeystore.jks</con:source>
    <con:password>ckpass</con:password>
    <con:type>KEYSTORE</con:type>
  </con:crypto>
  <con:outgoing mustUnderstand="true">
    <con:name>outgoing_config</con:name>
    <con:entry type="Username" username="Alice" password="ecilA">
      <con:configuration>
        <addCreated>true</addCreated>
        <addNonce>true</addNonce>
        <passwordType>PasswordText</passwordType>
      </con:configuration>
    </con:entry>
    <con:entry type="Timestamp">
      <con:configuration>
        <timeToLive>10000</timeToLive>
        <strictTimestamp>true</strictTimestamp>
      </con:configuration>
    </con:entry>
  </con:outgoing>
</con:wssContainer>
```

Points that are easy to get wrong:

- The element is `<con:outgoing>`. The name `outgoingWss` appears only as an **attribute on a request**
  (`outgoingWss="outgoing_config"`), selecting which configuration to apply. A project may hold several
  configurations of which only one is referenced.
- Children of `<con:configuration>` are unprefixed and lower camel case, unlike their `con:` parents.
- `<con:crypto type>` is `KEYSTORE` for signing and encryption keys, `TRUSTSTORE` for verification anchors.
- `<con:incoming>` blocks exist too, and map to the `inbound` list.
- Passwords are stored as plaintext, or as an encrypted project value. Either way they do not go into output.

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
| `useSingleCert` = false | `->withCertificatePath($chain)`, which sends the chain as `X509PKIPathv1` |
| `useSingleCert` = true | The default: the leaf certificate alone |
| `prependSignature` | No setting. Node order in the Security header is fixed here. |
| Parts table entries | See Parts below |
| No entry at all | No `Signature` block |

`keyIdentifierType` is stored as an Apache WSS4J `WSConstants` integer, not as the label the UI shows:

| Value | WSS4J name | SoapUI label | Ours |
|---|---|---|---|
| `0` | unset | (none chosen) | Treat as SoapUI's default and confirm against a captured message |
| `1` | `BST_DIRECT_REFERENCE` | Binary Security Token | `KeyRef::BinarySecurityToken` |
| `2` | `ISSUER_SERIAL` | Issuer Name and Serial Number | `KeyRef::IssuerSerial` |
| `3` | `X509_KEY_IDENTIFIER` | X509 Certificate | Unmapped. This puts the whole certificate in a `wsse:KeyIdentifier`, which this package does not emit. |
| `4` | `SKI_KEY_IDENTIFIER` | Subject Key Identifier | `KeyRef::SubjectKeyIdentifier` |
| `8` | `THUMBPRINT_IDENTIFIER` | Thumbprint SHA1 Identifier | `KeyRef::Thumbprint` |

If a project shows a value outside this set, do not guess. Open the entry in SoapUI, read the label, and map
from the label column.

This numeric mapping was derived from SoapUI's five dropdown labels, the values seen in the wild and WSS4J's
`WSConstants`, not confirmed against a project file containing a Signature entry. The label column is the part to
trust. If you have the project open, read the label and use it.

### `type="Encryption"`

| Field | Ours |
|---|---|
| `crypto` plus Alias | The recipient's certificate, as `Certificate` |
| `keyIdentifierType` | The same table, read as `EncKeyRef` instead of `KeyRef` |
| `symmetricEncAlgorithm` | `DataEncryptionMethod` |
| `keyEncryptionAlgorithm` | `KeyEncryptionMethod`, or `KeyTransportAlgorithm` when the OAEP hashes matter |
| `embeddedKeyName`, `embeddedKeyPassword` | Unmapped. A shared symmetric key is not supported; this package always wraps a fresh session key for the recipient. |
| Parts table entries | See Parts below |

### `type="SAML"` (XML form)

The assertion XML maps to `new Outbound\SamlAssertion($xml, $version)`. The form-based SAML entry, which mints
and signs an assertion inside SoapUI, has no counterpart: this package imports an assertion, it does not issue
one. Ask where the real assertion comes from.

## Parts

Both the Signature and Encryption entries carry a Parts table with `id`, `name`, `namespace` and `encode`
columns.

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
| `encode` = `Content` | The `Part::body()` default. Other parts default to `Element`, so use `->withEncryptionMode(EncryptionMode::Content)` when a row asks for Content. |
| `encode` = `Element` | `Part::body()->withEncryptionMode(EncryptionMode::Element)` for the Body; the default for every other part |

A long Parts table listing each header individually is usually better expressed as
`Part::securityHeaderContents()` or `Part::soapHeaders()`, which resolve against the live message. Say when you
make that substitution, since it can cover more than the original list.
