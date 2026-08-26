# php-soap/psr18-wsse-middleware domain glossary

Canonical terms for this domain. Every document, code comment, class name, and README section uses the
**Term** column verbatim; the Avoid column is banned in new writing. WS-Security / XML-DSig / XML-Enc /
WS-Addressing wire element names are spec-given and used exactly as the specs spell them.

## Configuration surface
| Term | Definition | Boundary | Source name(s) | Avoid |
|---|---|---|---|---|
| **WsseMiddleware** | The PSR-18 plugin that applies WS-Security to a SOAP exchange: outbound blocks secure the request, inbound blocks check the response | The whole plugin, not one operation — those are Blocks | `WsseMiddleware` (`src/WsseMiddleware.php:26`) | engine (as a synonym for the middleware) |
| **Block** | One self-configuring immutable unit dropped into the outbound or inbound list; its presence is its behaviour | The unit added to a list; NOT the per-message state (WsseContext) nor the shared settings (SecurityProfile) | `OutboundAction`/`InboundAction` (`src/WSSecurity/Outbound/OutboundAction.php:16`); "block" (`README.md#the-building-blocks`) | Action, building block, value object (as its name), Entry (legacy) |
| **Outbound** | The ordered list of blocks that secure the request being sent | Direction of send; pairs with Inbound | `$outbound` (`src/WsseMiddleware.php:34`) | outgoing |
| **Inbound** | The ordered list of blocks that check the response received | Direction of receive; pairs with Outbound | `$inbound` (`src/WsseMiddleware.php:35`) | incoming |
| **SecurityProfile** | The shared-settings value object carrying the WS-Security timestamp window and composing a CryptoPolicy; reaches every block via the context | Required first constructor argument of WsseMiddleware; holds only the window + a CryptoPolicy (the algorithm settings live on CryptoPolicy) | `SecurityProfile` (`src/WSSecurity/SecurityProfile.php:16`) | profile config, settings |
| **CryptoPolicy** | The XML-Security algorithm policy: outbound algorithm choices + inbound accept allow-lists, independent of SOAP so the engine can be driven without the WS-Security profile | The algorithm half split out of SecurityProfile; reached via `SecurityProfile::crypto()` | `CryptoPolicy` (`src/XmlSecurity/CryptoPolicy.php:20`) | profile (as its name), algorithm config |
| **WsseContext** | The per-message state (document + SOAP version + effective profile) each block acts on | One per message; carries only what is unique to the message in flight, not injected services | `WsseContext` (`src/WSSecurity/WsseContext.php:15`) | context (bare), message state |
| **Engine service** | A swappable per-block crypto service (signer, encryptor, decryptor, verifier); each concrete wires its own secure default via a static `create()` named constructor, and advanced users may replace it | The pluggable crypto implementation behind a block; NOT the WsseMiddleware and NOT one Block | `Signer::create()` (`src/XmlSecurity/Signing/Signer.php`) and the Verifier/Encryptor/Decryptor twins; "engine service" (`docs/xmlsecurity.md`) | engine, security engine (as synonyms for the middleware), DefaultEngine (removed) |

## Message parts
| Term | Definition | Boundary | Source name(s) | Avoid |
|---|---|---|---|---|
| **Part** | The WS-Security descriptor naming which region of a message a block targets, carrying the SOAP shortcuts (Body, Timestamp) plus generic Element/Path/Id; `toTarget(SoapVersion)` lowers it to a Target at the WSSE boundary | The WSSE-layer descriptor with SOAP knowledge; it lowers to a Target, which is the SOAP-free engine input | `Part` (`src/WSSecurity/Part.php:10`); `PartKind` (`src/WSSecurity/PartKind.php`) | target, region |
| **Target** | The generic XML-Security region descriptor the engine resolves and acts on: an element by qualified name (`Target::element`), an element by id (`Target::byId`), or an element by its position (`Target::path`); no SOAP Body/Timestamp notion | The SOAP-free engine input Part lowers to; `TargetKind` is Element/Id/Path. Resolved to a DOM node by `TargetLocator` | `Target` (`src/XmlSecurity/Target.php`); `TargetKind` (`src/XmlSecurity/TargetKind.php`); `TargetLocator` (`src/XmlSecurity/TargetLocator.php`) | part (in the engine), region |
| **Body** | The SOAP Body element, targeted by `Part::body()`, lowered to `Target::path(envelopeNs:Envelope, envelopeNs:Body)` so it is addressed by position and not by name alone | | `PartKind::Body` (`src/WSSecurity/PartKind.php`) | payload |
| **Element (part)** | A part identified by qualified name (namespace + local name) via `Part::element()` / `Target::element()`, found wherever it sits in the message | Addressed by QName anywhere; contrast Path (part), which fixes where it sits, and Id (part), addressed by wsu:Id | `PartKind::Element` (`src/WSSecurity/PartKind.php`); `TargetKind::Element` | node |
| **Path (part)** | A part identified by *where it sits*: an ordered list of QualifiedName steps walked from the document element down, each matching exactly one direct child of the one before it. Via `Part::path()` / `Target::path()` | Addressed by position, so a same-named element elsewhere never satisfies it; contrast Element (part), which is satisfied by the name anywhere. The first step names the document element itself | `PartKind::Path`; `TargetKind::Path`; `Target::path()` (`src/XmlSecurity/Target.php`) | xpath target, absolute path (as its name) |
| **QualifiedName** | A namespace URI paired with a local name, held together so neither travels without the other; one step of a Path | The name pair; NOT the element it matches. Defers the comparison rule to `ElementName` | `QualifiedName` (`src/Xml/QualifiedName.php`) | QName (in prose), tag name |
| **Id (part)** | A part identified by its `wsu:Id` via `Part::byId()` / `Target::byId()` | Addressed by wsu:Id; contrast Element (part), by QName | `PartKind::Id` (`src/WSSecurity/PartKind.php`); `TargetKind::Id` | reference |

## Id minting
| Term | Definition | Boundary | Source name(s) | Avoid |
|---|---|---|---|---|
| **IdMinter** | The engine SPI that stamps a document-unique id onto a node so a `ds:Reference`/`xenc:DataReference` can address it by `URI="#id"`; injected into `Signer::create()`/`Encryptor::create()` | The id-convention seam; a profile overrides which id attribute is used. NOT the Target (what to sign), and NOT the key reference | `IdMinter` (`src/XmlSecurity/IdMinter.php`) | id generator, id stamper |
| **XmlIdMinter** | The engine's shipped default IdMinter: stamps the W3C-standard `xml:id`, so a standalone (non-SOAP) caller signs/encrypts with zero config | The SOAP-free default; no in-package consumer yet (WSSE always injects the wsu:Id minter) — forward-looking for the standalone goal | `XmlIdMinter` (`src/XmlSecurity/XmlIdMinter.php`) | default minter (as its name) |
| **WsuIdMinter** | The WS-Security profile's IdMinter: stamps `wsu:Id`, as the spec mandates; the blocks inject it so signed and encrypted parts carry `wsu:Id` | The WSSE override of IdMinter; keeps the WSSE wire format | `WsuIdMinter` (`src/WSSecurity/Xml/Manipulator/WsuIdMinter.php`) | — |

## Outbound blocks
| Term | Definition | Boundary | Source name(s) | Avoid |
|---|---|---|---|---|
| **Timestamp (block)** | The outbound block writing a `wsu:Timestamp` (Created / Expires) so the receiver can reject stale or replayed calls | Produces the timestamp; the Timestamp Part references it, and ValidateTimestamp checks it inbound | `Outbound\Timestamp` (`src/WSSecurity/Outbound/Timestamp.php`) | — |
| **UsernameToken** | The outbound block adding a `wsse:UsernameToken` carrying caller credentials (PasswordText, PasswordDigest, or none) | | `Outbound\Username` (`src/WSSecurity/Outbound/Username.php`) | Username (bare), credentials token |
| **BinarySecurityToken (BST)** | The outbound block embedding an X.509 certificate as a base64-DER `wsse:BinarySecurityToken` so the receiver has the signer's public key | The wire token; also a key-reference type (see Key reference) that points at this embedded token | `Outbound\BinarySecurityToken` (`src/WSSecurity/Outbound/BinarySecurityToken.php`) | BST cert, binary token |
| **Signature (block)** | The outbound block adding a detached, multi-reference `ds:Signature` to the Security header | Produces the signature; VerifySignature is its inbound counterpart | `Outbound\Signature` (`src/WSSecurity/Outbound/Signature.php`) | signing block |
| **Encryption (block)** | The outbound block encrypting requested parts via XML-Enc, wrapping a fresh session key for the recipient | Produces ciphertext; Decrypt is its inbound counterpart | `Outbound\Encryption` (`src/WSSecurity/Outbound/Encryption.php`) | encrypt block |
| **SamlAssertion (block)** | The outbound block importing a SAML 1.1/2.0 assertion (issued by an STS) verbatim into the Security header | Imports an existing assertion with its signature; never re-mints its id | `Outbound\SamlAssertion` (`src/WSSecurity/Outbound/SamlAssertion.php`) | SAML token |

## Inbound blocks
| Term | Definition | Boundary | Source name(s) | Avoid |
|---|---|---|---|---|
| **Decrypt** | The inbound block decrypting `xenc:EncryptedData` parts of the response with your private key | Inbound counterpart of the Encryption block | `Inbound\Decrypt` (`src/WSSecurity/Inbound/Decrypt.php`) | decryption block |
| **VerifySignature** | The inbound block verifying the response signature and confirming required parts were signed by a trusted certificate | Inbound counterpart of the Signature block | `Inbound\VerifySignature` (`src/WSSecurity/Inbound/VerifySignature.php`) | signature check |
| **ValidateTimestamp** | The inbound block rejecting a stale, future-dated, or replayed-window response timestamp | Inbound counterpart of the Timestamp block; uses the freshness window | `Inbound\ValidateTimestamp` (`src/WSSecurity/Inbound/ValidateTimestamp.php`) | timestamp check |

## Key references
| Term | Definition | Boundary | Source name(s) | Avoid |
|---|---|---|---|---|
| **Key reference** | How a certificate is pointed at inside `ds:KeyInfo` (signing) or `xenc:EncryptedKey` (encryption): one of Direct reference, Subject Key Identifier, Issuer/Serial, Thumbprint | The umbrella concept; the outbound choice is made via KeyRef (signing) or EncKeyRef (encryption) | `KeyIdentifier` (`src/XmlSecurity/KeyIdentifier.php:15`) | key info, cert pointer |
| **KeyRef** | The enum selecting the key-reference type for the **Signature** block (default: BinarySecurityToken direct reference) | Signing direction; EncKeyRef is the encryption-direction twin | `KeyRef` (`src/WSSecurity/Outbound/KeyReference/KeyRef.php`) | — |
| **EncKeyRef** | The enum selecting the key-reference type for the **Encryption** block (default: SubjectKeyIdentifier) | Encryption direction; KeyRef is the signing-direction twin | `EncKeyRef` (`src/WSSecurity/Outbound/KeyReference/EncKeyRef.php`) | — |
| **Direct reference** | The X.509 interop default: embed a `wsse:BinarySecurityToken` and point at it by `wsu:Id` through `wsse:Reference` | Points at an embedded token; the other three references derive from the certificate alone | `KeyRef::BinarySecurityToken`; "direct reference" (`docs/outbound-blocks.md#outbound-signature`) | reference (bare) |
| **Subject Key Identifier (SKI)** | An inline reference carrying the certificate's Subject Key Identifier extension value | | `SubjectKeyIdentifier` (`src/KeyStore/Metadata/SubjectKeyIdentifier.php:8`); value type `X509SubjectKeyIdentifier` | subject id |
| **Issuer/Serial** | An inline `ds:X509IssuerSerial` reference: issuer distinguished name plus certificate serial number | | `IssuerSerial` (`src/KeyStore/Metadata/IssuerSerial.php:6`) | issuer serial (spacing), X509IssuerSerial (in prose) |
| **Thumbprint** | An inline `ThumbprintSHA1` reference: the SHA-1 fingerprint of the DER certificate | The SHA-1 here identifies a cert; it is unrelated to the (rejected) SHA-1 signature digest | `Thumbprint` (`src/KeyStore/Metadata/Thumbprint.php:8`); value type `ThumbprintSha1` | fingerprint, ThumbprintSHA1 (in prose) |
| **EncryptedKeySHA1 reference** | A reference naming a **session key** rather than a certificate: `base64(SHA-1(wrapped cipher bytes))` in a `wsse:KeyIdentifier`, the WSS 1.1 form a symmetric signature uses by default | Names the key itself, so it survives the key travelling anywhere and across a correlated response; the digest is over the wrapped bytes, never over the plaintext key | `EncryptedKeySha1KeyIdentifier` (`src/WSSecurity/Outbound/KeyReference/EncryptedKeySha1KeyIdentifier.php`) | EncryptedKey thumbprint, key digest |
| **Local token reference** | A `wsse:Reference URI="#..."` naming an element the same Security header carries, with no ValueType because the element says what it is; used for a local `xenc:EncryptedKey` and a local `wsc:DerivedKeyToken`, and by every `xenc:EncryptedData` | Distinct from Direct reference, which names a `wsse:BinarySecurityToken` and repeats that token's ValueType | `LocalTokenKeyIdentifier` (`src/WSSecurity/Outbound/KeyReference/LocalTokenKeyIdentifier.php`) | direct reference (for this form), id reference |
| **Wire identifier** | The string an inbound reference names a symmetric key by, matched against what the exchange established: an EncryptedKeySHA1 value, a `#wsu:Id`, or a pre-shared key's agreed name | The lookup key, not the element and not the reference; carried on SymmetricKey and resolved through ExchangeKeys | `SymmetricKey::$wireIdentifiers` (`src/WSSecurity/Keys/SymmetricKey.php`) | key id, key name |

## Algorithms
| Term | Definition | Boundary | Source name(s) | Avoid |
|---|---|---|---|---|
| **SignatureMethod** | The asymmetric signature algorithm (key type + hash): RSA/DSA/ECDSA with SHA-1/256/384/512 | | `SignatureMethod` (`src/Algorithm/SignatureMethod.php:10`) | signing algorithm |
| **DigestMethod** | The hash used for each signature reference digest (and OAEP label digest): SHA-1/256/384/512, RIPEMD160 | The signature reference hash; NOT the UsernameToken password digest | `DigestMethod` (`src/Algorithm/DigestMethod.php:10`) | digest (bare) |
| **PasswordDigest** | The UsernameToken password hash `Base64(SHA1(nonce+created+password))` | A UsernameToken mechanism; unrelated to DigestMethod | "PasswordDigest" (`docs/outbound-blocks.md#outbound-username`) | password hash |
| **Canonicalization (C14N)** | The XML canonicalization method applied before signing/verifying: inclusive C14N or exclusive EXC_C14N (± comments) | Canonical XML 1.1 is not supported | `SignatureCanonicalization` (`src/Algorithm/SignatureCanonicalization.php:12`) | c14n (lowercase in prose) |
| **DataEncryptionMethod** | The bulk symmetric cipher encrypting message-part content: AES-128/192/256 in GCM or CBC, 3DES-CBC | The cipher for data; distinct from key transport (which wraps the session key) | `DataEncryptionMethod` (`src/Algorithm/DataEncryptionMethod.php:10`) | bulk cipher, bulk encryption, data cipher |
| **Key transport** | Wrapping the symmetric session key under the recipient's RSA key: RSA-OAEP, RSA-OAEP-MGF1P, or legacy RSA-1_5 | Protects the session key; DataEncryptionMethod protects the data. Two types split this: KeyEncryptionMethod (the URI) and KeyTransportAlgorithm (URI + the label and MGF hashes) | "key transport" (`docs/security-profile.md`) | key encryption, key wrapping |
| **KeyEncryptionMethod** | The enum naming the key-transport algorithm URI alone (RSA_1_5 / RSA_OAEP_MGF1P / RSA_OAEP) | The algorithm URI without the OAEP hash; KeyTransportAlgorithm pairs it with a hash | `KeyEncryptionMethod` (`src/Algorithm/KeyEncryptionMethod.php:10`) | — |
| **KeyTransportAlgorithm** | The value object pairing a KeyEncryptionMethod with the two hashes OAEP takes — the label hash and the MGF hash (`oaepSha1`, `oaepSha256`, `legacyMgf1p`, `rsa1_5`) | Method + hashes together; KeyEncryptionMethod is the method alone | `KeyTransportAlgorithm` (`src/Algorithm/KeyTransportAlgorithm.php:12`) | — |
| **OAEP hash** | A hash parameterizing RSA-OAEP: SHA-1 or SHA-256. One value type filling two independent roles — see Label hash and MGF hash | The enum of available hashes; which role it plays is decided by the field it sits in | `OaepHash` (`src/Algorithm/OaepHash.php:12`) | oaep digest |
| **Label hash** | The OAEP hash applied to the label, declared by `ds:DigestMethod` inside `xenc:EncryptionMethod` | Independent of the MGF hash: `rsa-oaep-mgf1p` fixes the mask to MGF1-SHA1 while leaving this free, which is what WSS4J emits with a SHA-256 digest | `labelHash` (`src/Algorithm/KeyTransportAlgorithm.php`) | oaep hash (bare, when the label is meant) |
| **MGF hash** | The OAEP hash seeding the MGF1 mask, declared by `xenc11:MGF` under the xenc11 `rsa-oaep` URI only | Fixed to SHA-1 by the legacy `rsa-oaep-mgf1p` URI, which takes no `xenc11:MGF` child at all | `mgfHash` (`src/Algorithm/KeyTransportAlgorithm.php`) | mask hash, mgf1 hash |
| **Allow-list** | A per-algorithm inbound acceptance set on the CryptoPolicy; anything not listed is rejected regardless of what the enums can represent | Governs inbound acceptance; the enums list every case "for parity" independent of the allow-list | `accepted*Methods` (`src/XmlSecurity/CryptoPolicy.php`) | whitelist, accepted methods (as the concept name) |

## Key material and credentials
| Term | Definition | Boundary | Source name(s) | Avoid |
|---|---|---|---|---|
| **Certificate** | A public X.509 certificate in PEM | Public cert only; ClientCertificate bundles it with a private key | `Certificate` (`src/KeyStore/Certificate.php:11`) | cert, public key |
| **Private key** | A PKCS#8 private key in PEM, optionally passphrase-protected | The signing/decryption secret; SessionKey is the symmetric counterpart | `Key` (`src/KeyStore/Key.php:10`) | key (bare — overloaded), secret key |
| **ClientCertificate** | A PEM bundle of a public certificate plus its PKCS#8 private key — your signing identity | Bundles a Certificate + a Private key; splits into both | `ClientCertificate` (`src/KeyStore/ClientCertificate.php:12`) | signing identity (as its name), cert-and-key bundle, credential |
| **PKCS#12 bundle** | A decoded PKCS#12 (.p12/.pfx): a leaf-first certificate chain, the private key, and any embedded CA chain (extracerts) | | `Pkcs12Bundle` (`src/KeyStore/Pkcs12Bundle.php:10`) | p12 blob, pfx, PKCS#12 blob |
| **Session key** | A symmetric key (raw bytes) that encrypts the message data, and may also key a MAC over it | Symmetric and per-exchange; distinct from the RSA Private key that wraps it. How it reaches the peer is the Symmetric key source's business, not this type's | `SessionKey` (`src/KeyStore/SessionKey.php:9`) | symmetric key (bare), data key |
| **Symmetric key source** | The recipe saying where a symmetric key comes from and how a `ds:KeyInfo` names it: a session key generated here and sent, a pre-shared secret, or a key derived from either | Holds no key: it is constructed once with the middleware and reused. Two blocks share one key by being handed the same **object**; identity is the sharing mechanism | `SymmetricKeySource` (`src/WSSecurity/Keys/SymmetricKeySource.php`) | key provider, key factory, key strategy |
| **Protection token** | The WS-SecurityPolicy term for the token a `sp:SymmetricBinding` keys both its signature and its encryption off | The policy-side name for what a Symmetric key source produces; use it when translating a policy, not in code | `sp:ProtectionToken` (`.agents/skills/wsse-import-wspolicy/references/ws-securitypolicy.md`) | protection key, shared token |
| **Deriving token** | The token a derived key derives **from**: the `xenc:EncryptedKey` or pre-shared secret a `wsc:DerivedKeyToken` references | The input of a derivation; the Derived key is its output. A derived key may not itself be a deriving token | `DerivedSessionKey::$from` (`src/WSSecurity/Keys/DerivedSessionKey.php`) | parent key, base key, source token (overloaded) |
| **Derived key** | A key produced from a deriving token with P_SHA1 and carried as a `wsc:DerivedKeyToken`, so the shared token is never used to sign or encrypt directly | One per use, at the length the consuming algorithm defines; what `sp:RequireDerivedKeys` asks for | `DerivedSessionKey` (`src/WSSecurity/Keys/DerivedSessionKey.php`) | derived session key (in prose), sub-key |
| **Signing key** | Which of the two kinds of signature a Signature block makes, and what keys it: `Signing\Asymmetric` is made with a private key and identifies its signer, `Signing\Symmetric` is a keyed MAC and identifies nobody | The mode, stated rather than inferred. Distinct from the Private key inside it, from the Symmetric key source it may wrap, and from the Key reference it resolves | `SigningKey` (`src/WSSecurity/Signing/SigningKey.php`) | credential (bare), signer |
| **ExchangeKeys** | The symmetric keys of one request/response exchange: which source materialized which key, and which wire identifier names which secret | One instance per exchange, shared by both directions and nothing wider: a longer-lived cache would let a response verify against another exchange's key | `ExchangeKeys` (`src/WSSecurity/Keys/ExchangeKeys.php`) | key cache, key bag, key registry |
| **PEM bundle** | One or more concatenated PEM certificates in a single file (e.g. trusted CAs / intermediates) | | `Pem` (`src/KeyStore/Pem.php:9`) | cert file |
| **Passphrase** | The secret decrypting an encrypted private key or PKCS#12 | | `withPassphrase()` (`docs/key-stores.md`) | password (for the key), passcode |

## Trust
| Term | Definition | Boundary | Source name(s) | Avoid |
|---|---|---|---|---|
| **TrustStore** | The set of trust anchors the inbound verifier accepts as valid signers | The anchors you trust; a CertificateChain is what the peer presents (untrusted) | `TrustStore` (`src/KeyStore/TrustStore.php:8`) | trusted certs, pinned certs (as the concept name) |
| **Trust anchor** | A pinned root certificate an incoming chain must chain up to | | `anchor` (`src/OpenSSL/CertificateTrust.php:76`) | root, CA (bare) |
| **CertificateChain** | An ordered leaf-first chain of certificates extracted from a BST or `ds:KeyInfo`; carries no trust of its own | Presented and untrusted until verified against the TrustStore | `CertificateChain` (`src/KeyStore/CertificateChain.php:8`) | cert path |
| **Leaf** | The first certificate in a chain — the end-entity (signer) certificate | | `leaf` (`src/KeyStore/CertificateChain.php:31`) | end cert |
| **Intermediates** | The certificates above the leaf, passed to the verifier as untrusted intermediate certificates | | `intermediates` (`src/KeyStore/CertificateChain.php:44`) | middle certs |
| **TrustedSigner** | The validated signer identity (subject DN + certificate) returned once trust is established | The verified result; CertificateChain is the unverified input | `TrustedSigner` (`src/KeyStore/TrustedSigner.php:8`) | verified signer, signer (bare) |

## Freshness and time
| Term | Definition | Boundary | Source name(s) | Avoid |
|---|---|---|---|---|
| **Timestamp TTL** | Seconds until Expires (outbound) and the maximum accepted age of an inbound timestamp — one value doing both jobs | Combines with clock skew to form the freshness window | `timestampTtl` (`src/WSSecurity/SecurityProfile.php:43`) | ttl (bare), lifetime, maxAge |
| **Clock skew** | The tolerance in seconds allowed when checking an inbound timestamp against the local clock | | `clockSkew` (`src/WSSecurity/SecurityProfile.php:44`) | tolerance, drift |
| **Freshness window** | The acceptance window for an inbound timestamp, formed by timestamp TTL + clock skew | A timestamp acceptance window; NOT the certificate ValidityWindow (notBefore/notAfter) | "freshness window" (`docs/security-profile.md`) | timestamp window, created/expires window |
| **ValidityWindow** | The certificate's notBefore/notAfter validity period, used to reject not-yet-valid or expired certs | A certificate's validity period; NOT the message Freshness window | `ValidityWindow` (`src/KeyStore/Metadata/ValidityWindow.php:8`) | validity period (as its name), cert window |
| **Clock** | The injectable source of "now" used for inbound timestamp and freshness checks | | `Clock` (`src/Clock/Clock.php:16`) | time source |

## SOAP envelope
| Term | Definition | Boundary | Source name(s) | Avoid |
|---|---|---|---|---|
| **SoapVersion** | SOAP 1.1 or 1.2, derived from the envelope at send time; determines the envelope namespace and next-hop targeting attribute | Detected from the document, never configured | `SoapVersion` (`src/WSSecurity/SoapVersion.php`) | soap ver |
| **mustUnderstand** | The Security-header attribute forcing the receiver to process the header or fault | | `mustUnderstand` (`src/WSSecurity/SoapVersion.php:12`) | must-understand |
| **actor/role** | The next-hop targeting attribute on the Security header: spelled `actor` in SOAP 1.1, `role` in SOAP 1.2 — one concept, two spec-mandated spellings | Null means the ultimate receiver | `actorOrRoleName()` (`src/WSSecurity/SoapVersion.php`) | recipient attr |

## WS-Addressing
| Term | Definition | Boundary | Source name(s) | Avoid |
|---|---|---|---|---|
| **WsaMiddleware** | The single PSR-18 plugin adding WS-Addressing headers, covering both addressing versions | | `WsaMiddleware` (`src/WsaMiddleware.php:17`) | WsaMiddleware2005 (removed) |
| **WsaOptions** | The options DTO carrying the addressing version plus every message-addressing property a caller wants to fix rather than let the middleware derive; the sole `WsaMiddleware` constructor argument | The outbound settings object; NOT the header it configures (WsaHeader), and it deliberately omits RelatesTo (a reply property) and MessageID (always freshly minted) | `WsaOptions` (`src/Wsa/WsaOptions.php:23`) | WsaProfile, WsaConfig, addressing options |
| **FaultTo** | The addressing header naming where the service sends a fault instead of to ReplyTo; absent means faults follow ReplyTo | | `withFaultTo()` (`src/Wsa/WsaHeader.php`) | fault endpoint, error address |
| **WsaNamespace** | The addressing version by URI: W3C 2005/08 (default) or the 2004/08 submission | | `WsaNamespace` (`src/Wsa/WsaNamespace.php:9`) | wsa version |
| **MessageID** | The globally unique message id (a v4 UUID with `uuid:` prefix) the receiver echoes back in `wsa:RelatesTo` | Wire element is `wsa:MessageID`; the PHP class is `MessageId` (casing differs) | `MessageId` (`src/Wsa/MessageId.php:8`) | message id (spacing), msg id |
| **RelatesTo** | The addressing header on a reply that correlates it to a request's MessageID | | `RelatesTo` (`src/Wsa/WsaHeader.php:83`) | correlation id |
| **Anonymous URI** | The default `ReplyTo` address when none is set, defined per addressing version | | `anonymousUri()` (`src/Wsa/WsaNamespace.php:22`) | anon address |

## SAML
| Term | Definition | Boundary | Source name(s) | Avoid |
|---|---|---|---|---|
| **SAML assertion** | A `saml:Assertion` (SAML 1.1 or 2.0) issued by an STS and imported verbatim into the Security header | Imported as-is with any existing signature | `SamlAssertion` (`src/WSSecurity/Outbound/SamlAssertion.php`) | assertion (bare), SAML token |
| **SamlVersion** | SAML 1.1 vs 2.0, distinguished by namespace and id attribute (`AssertionID` for 1.1, `ID` for 2.0) | | `SamlVersion` (`src/WSSecurity/Outbound/SamlVersion.php:6`) | saml ver |
| **STS (Security Token Service)** | The external service that issues the SAML assertion | | "STS" (`docs/outbound-blocks.md#outbound-samlassertion`) | token service, IdP |
| **Holder-of-Key** | The SAML confirmation flow that wires the assertion id into a signature to prove possession | | "Holder-of-Key" (`docs/outbound-blocks.md#outbound-samlassertion`) | HoK, holder of key |

## Security design vocabulary
| Term | Definition | Boundary | Source name(s) | Avoid |
|---|---|---|---|---|
| **Oracle** | A response difference that lets a peer distinguish failure causes (padding oracle, forgery oracle); the design exists to expose none | The threat the uniform-fault design defends against | "oracle" (`docs/inbound-blocks.md`) | leak, side channel (as synonyms) |
| **SecurityFault** | The single uniform inbound failure that reveals nothing about which step failed (the real cause is chained for logs only) | Every inbound failure collapses to this; outbound failures use distinct exceptions | `SecurityFault` (`src/WSSecurity/Exception/SecurityFault.php:9`) | security error, generic error |
| **DOCTYPE rejection** | Rejecting any DOCTYPE before any block parses the document, as XXE defense | Applies to every parse, including SAML assertions parsed in isolation | `disallow_doctype()` (`src/WsseMiddleware.php:18`) | doctype block, XXE guard |
| **XSW (XML Signature Wrapping)** | The attack class of moving or duplicating signed content so a signature validates over the wrong element; drives id-resolution and covered-part hardening | `SignatureLocator` (`src/XmlSecurity/Verification/SignedInfo/SignatureLocator.php`), `RequiredPartsValidator` (`src/WSSecurity/Validator/RequiredPartsValidator.php`) | wrapping attack (bare), signature wrapping |

## External parts and attachments
_Naming fixed so it stops being re-litigated. "Complete" here always means the profile's coverage variant
and never "finished"._

| Term | Definition | Boundary | Source name(s) | Avoid |
|---|---|---|---|---|
| **External part** | A part of the message whose bytes live outside the XML document and are addressed by URI rather than by id | The counterpart of a Part: a Part names a region *of* the document, an external part names bytes the document only points at. Both encryptable and signable | `ExternalPart` (blueprint) | detached part (see Avoid note below), MIME part, attachment (when the engine is meant), external reference |
| **ExternalPartList** | The collection of external parts for one message, in which no two parts share a reference | Holds the uniqueness rule; NOT the seam that supplies it | `ExternalPartList` (blueprint) | parts array, external parts (as its name) |
| **ExternalParts** | The seam a block reads external parts from and writes the transformed ones back to, so the engine names nothing outside this package | The supply-and-return contract; NOT the collection it moves. `collect()` reads what a signature covers and `collectSealed()` what a cipher addresses, the two differing only in Digest prefix; `replace()` fully replaces the parts it is handed and touches nothing else | `ExternalParts` | store, port, provider, repository, apply (as the write method) |
| **Coverage** | How much of an external part a protection covers: its content alone, or its transport metadata as well | A property of the adapter, read by the block, never a parameter threaded through the seam. Inbound it is a requirement rather than a hint | `ExternalPartCoverage` | scope, mode, transform (as its name), completeness |
| **Header block** | The MIME headers that precede a part's bytes when a coverage includes its metadata | Two forms exist and only one is implemented: the canonical form a digest is taken over, and the verbatim form a complete encryption would prepend | `MimeHeaderBlock` | preamble, MIME preface, headers (bare) |
| **Canonical header block** | The digest form of a header block: the profile headers a part carries, normalized, ascending by name, one CRLF each and no blank line | What both stacks must agree on byte for byte; distinct from the header set an attachment carries, which is unnormalized. Four of the profile's five can appear in it, since a part carrying `Content-Description` is refused rather than canonicalized | `MimeHeaderBlock::canonicalize()` | canonicalized headers, header canonicalization (as the artifact) |
| **Reference (external)** | The URI an external part is addressed by, used verbatim as the `xenc:CipherReference` URI and as the lookup key | For an attachment it is the `cid:` form of the Content-ID; the engine never parses or builds it | `ExternalPart::$reference` (blueprint) | href, cid (bare), id |
| **Sealed part** | An external part after encryption: same reference, ciphertext for content, opaque media type | Outbound result; the inbound twin is an Opened part | "sealed part" (blueprint) | encrypted part, cipher part |
| **Opened part** | An external part after decryption: same reference, plaintext for content, original media type restored | Inbound result; the outbound twin is a Sealed part | "opened part" (blueprint) | decrypted part, plain part |
| **Attachment** | One file carried beside the SOAP envelope as its own MIME part, identified by a Content-ID that never changes while its bytes and media type may be replaced | The file, not the pointer to it; owned by the attachments middleware, not by this package. An attachment presented to the engine becomes an External part | `Attachment` (php-soap/psr18-attachments-middleware) | file, payload, part (bare) |
| **AttachmentParts** | The shipped implementation of ExternalParts over the attachments middleware's storage, one instance per direction | The only place in this package that names the attachments middleware; deliberately not named after SwA, because the mechanism is identical under MTOM | `AttachmentParts` (blueprint) | SwaAttachments, attachment store, adapter (as its name) |
| **SwA** | The packaging where attachments are separate MIME parts that the XML never contains, referenced by `cid:` | Distinct from MTOM only in packaging labels; identical from this package's point of view | "SwA" (WSS SwA Profile 1.1) | SOAP with attachments (in code), swa (lowercase) |
| **MTOM / XOP** | The packaging where an element's own value is carried in a MIME part, with an `xop:Include` standing in its place inside the XML | The element's value lives elsewhere but still *belongs* to the element; encrypting the element that holds the include covers only the pointer, which is why that is refused | "MTOM", "XOP" (`xop:Include`) | optimization (bare), inline attachment |
| **Attachment-Content-Only** | The encryption mode covering an attachment's content while its MIME headers stay readable | The only mode emitted; Attachment-Complete, which also covers the headers, is accepted inbound and not emitted | `Attachment-Content-Only` (WSS SwA Profile 1.1) | content mode, partial encryption |
| **Ciphertext transform** | The transform declared inside a `xenc:CipherReference` telling a receiver the referenced part holds ciphertext | Declared, never applied by us; one per reference | `Attachment-Ciphertext-Transform` (WSS SwA Profile 1.1) | cipher transform, decode transform |
| **Content transform** | The signature transform declaring that a reference's digest covers an attachment's content and none of its MIME headers | The signing twin of the Ciphertext transform. It is not the identity: it also performs Content canonicalization. Its Complete counterpart covers the canonical header block as well, and a bare `sp:Attachments` policy means that one | `Attachment-Content-Signature-Transform` (WSS SwA Profile 1.1) | attachment transform, body transform |
| **Complete transform** | The signature transform declaring that a reference's digest covers an attachment's canonical header block as well as its content | What a bare `sp:Attachments` means; content-only is the opt-in | `Attachment-Complete-Signature-Transform` (WSS SwA Profile 1.1) | full transform, element transform |
| **Content canonicalization** | The media-type-dependent step inside a content or complete transform that turns a part's bytes into the octets actually digested: XML through exclusive C14N, any other text with its line endings normalized to CRLF, everything else unchanged | A step *within* a transform, never a transform itself, which is why it names no URI. Distinct from the Canonical header block, which is metadata and is never put through it | `ExternalPartContent` | content normalization, part canonicalization, transform (as its name) |
| **Digest prefix** | The bytes a signature digests ahead of a part's transformed content, carrying the canonical header block under a complete coverage and empty otherwise | Kept beside the content rather than joined to it, because only the content goes through Content canonicalization; the engine joins the two after transforming | `ExternalPart::$digestPrefix` | header prefix, composed octets, preamble |
| **Signed reference** | One `ds:Reference` ready to emit, carrying its own URI, digest, digest method and transform chain instead of having them derived from an element id | Replaces the element-only DigestResult, so an element reference and an external one are the same kind of thing to the SignedInfo builder | `SignedReference` (blueprint) | digest result, reference (bare) |

## Flagged ambiguities
_None open. Three coined-term forks were resolved by the user and are recorded in the tables above: Block vs
Action and key-transport naming (2026-07-07), and the external-part naming (2026-08-25)._

**Why "detached" is banned for an external part.** It already carries two unrelated meanings in this project:
an element not attached to the document tree, and a signature that neither envelops nor is enveloped by what
it signs. A third meaning would make the word useless. **Why not "MIME part":** the concept lives in the
SOAP-free engine layer, which holds no transport vocabulary, and the URI a part is addressed by need not be a
`cid:` at all.

## Notes (contradictions to fix in the code/docs, not glossary forks)
_None open — the SecurityProfile "Optional vs required" docblock contradiction was resolved when SecurityProfile
was split (its docblock no longer calls it "Optional"; it is the required first WsseMiddleware argument)._
