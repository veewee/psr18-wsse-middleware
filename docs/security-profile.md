# Security profile and defaults

[← Back to the deep dives](../README.md#deep-dives)

You configure a `SecurityProfile` once on the `WsseMiddleware` and it reaches every block through the
per-message context. Outbound blocks read their algorithm choices and the timestamp window from it (and let you
override per block); inbound blocks read the accept allow-lists and the freshness window from it.

```php
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\KeyEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;

// Secure defaults: equivalent to SecurityProfile::default():
$profile = new SecurityProfile();

// A fully spelled-out profile: the WS-Security timestamp window plus an XML-Security CryptoPolicy that
// carries the algorithm choices and the inbound accept allow-lists.
$profile = new SecurityProfile(
    timestampTtl: 300,
    clockSkew: 60,
    crypto: new CryptoPolicy(
        signatureMethod: SignatureMethod::RSA_SHA256,
        digestMethod: DigestMethod::SHA256,
        canonicalization: SignatureCanonicalization::EXC_C14N,
        dataEncryptionMethod: DataEncryptionMethod::AES256_GCM,
        keyEncryptionMethod: KeyEncryptionMethod::RSA_OAEP,
    ),
);
```

## The defaults at a glance

Everything `new SecurityProfile()` gives you, and where to change it. Outbound choices can also be overridden
per block; the inbound allow-lists cannot, because they are the floor.

| Setting | Default | Direction |
|---|---|---|
| `timestampTtl` | 300 seconds | Both: the window you send and the maximum age you accept |
| `clockSkew` | 60 seconds | Inbound tolerance against the local clock |
| `actorOrRole` | `null`, the ultimate receiver | Both: which header is written and which is read |
| `mustUnderstand` | `true` | Outbound |
| `wsSecureConversation` | `V2005_12` | Outbound only; both dialects are read |
| `signatureMethod` | `RSA_SHA256` | Outbound |
| `digestMethod` | `SHA256` | Outbound |
| `canonicalization` | `EXC_C14N` | Outbound |
| `dataEncryptionMethod` | `AES256_GCM` | Outbound |
| `keyEncryptionMethod` | `RSA_OAEP` | Outbound |
| `oaepHash` | `Sha1` | Outbound |
| `acceptedSignatureMethods` | RSA, ECDSA and HMAC at SHA-256/384/512 | Inbound |
| `acceptedDigestMethods` | SHA-256/384/512 | Inbound |
| `acceptedCanonicalizations` | the exclusive variants only | Inbound |
| `acceptedDataEncryptionMethods` | the three GCM ciphers only | Inbound |
| `acceptedKeyEncryptionMethods` | RSA-OAEP and RSA-OAEP-MGF1P | Inbound |
| `acceptedOaepHashes` | SHA-1 and SHA-256 | Inbound |
| `minimumRsaKeyBits` | 1024. **Raise to 2048 if your peer allows** | Inbound |
| `minimumEcKeyBits` | 224 | Inbound |

The three you are most likely to need to change are `acceptedDataEncryptionMethods` (a .NET/WCF peer offers only
CBC), `acceptedSignatureMethods` (an older algorithm suite pins SHA-1), and `acceptedCanonicalizations` (a peer
whose references carry no `ds:Transforms`). Each costs something, and
[What is rejected inbound by default](#what-is-rejected-inbound-by-default-and-why) is the table of what.

`SecurityProfile` carries the WS-Security freshness window, how the Security header is targeted, and composes a
`CryptoPolicy`:

- `int $timestampTtl = 300`: the outbound timestamp window in seconds, and the maximum accepted age of an
  inbound timestamp.
- `int $clockSkew = 60`: the tolerance, in seconds, applied when checking an inbound timestamp against the
  local clock.
- `?CryptoPolicy $crypto = null`: the XML-Security algorithm policy below; `null` uses `CryptoPolicy::default()`.
- `?string $actorOrRole = null`: which hop this exchange belongs to, spelled `soap:actor` in SOAP 1.1 and
  `soap:role` in SOAP 1.2. `null` (default) means the ultimate receiver, whose header carries no such attribute.

  One value does both jobs, because both answer the same question, and both resolve the header the same way.
  Outbound it targets the header the blocks write into: an existing header addressed to a different hop is left
  alone and a new one is created for your target, so your tokens are never appended into another node's header
  and an existing header is never silently re-addressed. Inbound it selects the header the blocks read, so a
  signature or timestamp in a header addressed to a different hop is not treated as yours. In both directions a
  message carrying two headers addressed to you is refused rather than one being picked. Set it only if your
  deployment is addressed as a named intermediary:

  ```php
  $profile = new SecurityProfile(actorOrRole: 'urn:my-gateway');
  ```
- `bool $mustUnderstand = true`: whether the outbound Security header demands the receiver process it or
  fault. Leave it on unless a peer rejects the attribute.
- `WsSecureConversationVersion $wsSecureConversation = WsSecureConversationVersion::V2005_12`: which
  WS-SecureConversation dialect an emitted `wsc:DerivedKeyToken` is written in. The default is the OASIS
  revision a modern peer expects; `V2005_02` is the earlier draft that shipped in older stacks. This governs
  what is **emitted** only. Both are read on the way in, because which one a peer writes is not something a
  client gets to constrain.

  ```php
  use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsSecureConversationVersion;

  $profile = new SecurityProfile(wsSecureConversation: WsSecureConversationVersion::V2005_02);
  ```

`CryptoPolicy` (namespace `Soap\Psr18WsseMiddleware\XmlSecurity`) carries the algorithm choices and allow-lists,
and can be used to drive the signing/encryption layer without the SOAP profile:

- `SignatureMethod $signatureMethod = SignatureMethod::RSA_SHA256`: the outbound signature algorithm.
- `OaepHash $oaepHash = OaepHash::Sha1`: the OAEP label hash every outbound `Encryption` block uses unless its
  key source states the whole key transport itself. Set it here to move every block to SHA-256 at once, rather
  than passing `keyTransportAlgorithm:` to each key source and having one added later fall back to SHA-1.
- `DigestMethod $digestMethod = DigestMethod::SHA256`: the outbound per-reference digest.
- `SignatureCanonicalization $canonicalization = SignatureCanonicalization::EXC_C14N`: the outbound
  canonicalization method.
- `DataEncryptionMethod $dataEncryptionMethod = DataEncryptionMethod::AES256_GCM`: the outbound bulk cipher.
- `KeyEncryptionMethod $keyEncryptionMethod = KeyEncryptionMethod::RSA_OAEP`: the outbound key-transport
  algorithm.
- `?array $acceptedSignatureMethods = null`: the inbound allow-list for signature algorithms. `null` (default)
  applies secure defaults: RSA-SHA256/384/512, ECDSA-SHA256/384/512 and HMAC-SHA256/384/512, rejecting every
  SHA-1 method and HMAC-SHA224.

  The HMAC methods are keyed by a shared secret. They are accepted by default under the same rule their RSA
  counterparts follow, and that costs a deployment which establishes no symmetric secret nothing: the verifier
  refuses an HMAC signature whose `ds:KeyInfo` resolved to a certificate, and a deployment with no established
  secret has nothing else such a reference could resolve to. See
  [What is rejected inbound by default](#what-is-rejected-inbound-by-default-and-why).
- `?array $acceptedDigestMethods = null`: the inbound allow-list for digests. Default: SHA-256/384/512.
- `?array $acceptedKeyEncryptionMethods = null`: the inbound allow-list for key transport. Default: RSA-OAEP and
  RSA-OAEP-MGF1P, rejecting RSA-1_5.
- `?array $acceptedDataEncryptionMethods = null`: the inbound allow-list for bulk ciphers. Default: the three
  GCM ciphers only. AES-CBC and 3DES are rejected until you name them, because only GCM authenticates its own
  ciphertext and nothing here requires an encrypted part to also be covered by a verified signature. See
  [What is rejected inbound by default](#what-is-rejected-inbound-by-default-and-why) for what accepting CBC
  costs. A peer that cannot encrypt with GCM (any .NET/WCF service, for one) needs it listed:
  ```php
  use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;

  $profile = new SecurityProfile(crypto: new CryptoPolicy(
      acceptedDataEncryptionMethods: [
          DataEncryptionMethod::AES256_GCM,
          DataEncryptionMethod::AES256_CBC, // only for a peer that offers nothing better
      ],
  ));
  ```
- `?array $acceptedOaepHashes = null`: the inbound allow-list for the OAEP hash on an inbound `EncryptedKey`.
  Default: SHA-1 and SHA-256.
- `int $minimumRsaKeyBits = 1024`: the smallest RSA (or DSA) signer key accepted inbound. The allow-lists gate
  *which* algorithm a peer may use, not how big its key is, and OpenSSL's certificate-path validation carries no
  key-size policy of its own (its security levels govern TLS handshakes, not chains), so without this a 512-bit
  RSA signer chaining to your anchor is accepted. The default admits the sizes legacy WS-Security services still
  run and refuses only the sizes that are broken outright: 512-bit RSA is factorable in hours. **Raise it to
  `2048` if your peer allows**: this is a client library, so you cannot choose the server's key, but you can
  refuse to accept a bad one.
- `int $minimumEcKeyBits = 224`: the same floor for elliptic-curve signers, measured separately because 256 bits
  is a strong EC key and a broken RSA one. P-256 and up clear it.
- `?array $acceptedCanonicalizations = null`: the inbound allow-list for the canonicalization on an inbound
  signature. Default: the exclusive variants only (`SignatureCanonicalization::EXC_C14N` and
  `EXC_C14N_COMMENTS`). The inclusive variants are not the WSSE norm, so accepting them only widens the attack
  surface; opt in by listing `SignatureCanonicalization::C14N` and/or `C14N_COMMENTS` here:
  ```php
  use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;

  $profile = new SecurityProfile(crypto: new CryptoPolicy(
      acceptedCanonicalizations: [
          SignatureCanonicalization::EXC_C14N,
          SignatureCanonicalization::EXC_C14N_COMMENTS,
          SignatureCanonicalization::C14N,
      ],
  ));
  ```
  This is also what a peer whose `ds:Reference` elements carry no `ds:Transforms` needs. XML-DSig digests such
  a reference under inclusive canonicalization: `ds:SignedInfo`'s own `CanonicalizationMethod` covers only
  `ds:SignedInfo`. So with the exclusive-only default those signatures are refused. Listing
  `SignatureCanonicalization::C14N` above is the supported way to verify them.

The defaults reject weak algorithms (SHA-1, RSA-1_5, 3DES), and use SHA-256 with exclusive canonicalization. The
algorithm enums live under `Soap\Psr18WsseMiddleware\Algorithm\`: `SignatureMethod`, `DigestMethod`,
`SignatureCanonicalization`, `DataEncryptionMethod`, `KeyEncryptionMethod`, `KeyTransportAlgorithm` and
`OaepHash`.

### Two inbound refusals no allow-list can lift

- **`ds:HMACOutputLength` is refused outright.** Truncating a MAC shrinks the value a forgery has to hit: cut to
  one byte a forgery succeeds once in 256 attempts, and at one bit it is a coin flip. No peer needs truncation,
  so the element is refused where `ds:SignedInfo` is read, before anything is computed, whatever length it names.
- **An HMAC signature method must have resolved to a secret, and an asymmetric one to a certificate.** Pairing an
  HMAC method with a certificate-resolved key is the algorithm-confusion forgery: the "secret" would be the
  peer's public key bytes, which anyone holding the certificate has. The mirror case is refused too, since an
  asymmetric method answered with a secret would skip the trust decision entirely. Neither is a configuration
  mistake to be resolved in the caller's favour.

## Supported algorithms and limitations

- **Signatures:** RSA-SHA256/384/512, ECDSA-SHA256/384/512 and HMAC-SHA256/384/512. RSA-SHA1, HMAC-SHA1 and
  HMAC-SHA224 are rejected by default. ECDSA needs an EC certificate and key; the HMAC methods need a
  [symmetric key source](outbound-blocks.md#symmetric-key-sources) rather than a certificate.
- **Digests:** SHA-256/384/512. SHA-1 is rejected by default.
- **Key transport:** RSA-OAEP-SHA1 (the default), RSA-OAEP-SHA256,
  RSA-OAEP-MGF1P and RSA-1_5 (rejected by default). Select a non-default on the
  [`GeneratedSessionKey`](outbound-blocks.md#symmetric-key-sources) that wraps the key.
- **Key derivation:** P_SHA1, in both WS-SecureConversation dialects. It is the only function either dialect
  defines, so there is nothing to select: a peer computing anything else would derive a different key.
- **Bulk encryption:** AES-GCM at 128/192/256 bits. AES-CBC and 3DES are rejected by default.
- **Signer key sizes:** `minimumRsaKeyBits` (1024) and `minimumEcKeyBits` (224) floor the signer's public key,
  which no chain validation checks for you. The floor is fail-closed: a key whose family or size cannot be read
  is refused rather than waved through, because the verdict comes from `ext-openssl` while the signature is
  verified with phpseclib, and a key one cannot read is not thereby a key the other cannot use.
- **Reference transforms:** the enveloped-signature transform, the four canonicalizations below, and the
  WS-Security `#STR-Transform`, which digests the token a `wsse:SecurityTokenReference` names instead of the
  reference element. Its digest input states the empty default namespace on the token, whatever default was
  in scope, which is what the peers emitting it produce; a token inheriting a default namespace is therefore
  digested as though none applied. The last is accepted without opting in, because it is neither weak nor unauthenticated:
  the canonicalization it names inside its own parameters is still gated by the allow-list below. Its
  certificate-naming forms (Subject Key Identifier, thumbprint, issuer and serial) are refused; see
  [Inbound blocks](inbound-blocks.md#inbound-verifysignature). No other transform is accepted: an XPath or
  XSLT transform lets a signature cover something other than the element it points at, and neither is a
  WS-Security norm.
- **Canonicalization:** exclusive C14N (`EXC_C14N`, `EXC_C14N_COMMENTS`) is the default and the only form
  accepted inbound unless you opt in. Inclusive Canonical XML 1.0 (`C14N`, `C14N_COMMENTS`) is supported as an
  opt-in. Canonical XML 1.1 is **not** supported: the underlying platform does not provide it.

## What is rejected inbound by default, and why

One rule governs every allow-list: **an algorithm that is sound on its own is accepted; anything weak,
broken, or unauthenticated has to be named.** So an integration never inherits a weakness by accident, and
reaching a peer that offers nothing better is always a deliberate, greppable line in your configuration.

The table is the full set. Each entry is refused inbound until you list it in the matching `CryptoPolicy`
allow-list, and the risk column is what you are accepting when you do.

| Algorithm | Opt in via | What you are accepting |
|---|---|---|
| **AES-CBC** 128/192/256 | `acceptedDataEncryptionMethods` | CBC carries no integrity of its own, and no block here ties a decrypted part to a region a verified signature covered. A party who can make your client send requests can replay a captured `xenc:EncryptedKey` next to a mangled `CipherValue` and read accept-or-reject from each reply, recovering **your peer's plaintext byte by byte** (CVE-2011-1096). It is a confidentiality break, not merely a missing integrity check. Note this is what .NET/WCF services emit: every standard `SecurityAlgorithmSuite` is CBC and none offer GCM, so a WCF peer leaves you no choice |
| **3DES-CBC** | `acceptedDataEncryptionMethods` | All of the above, plus a 64-bit block, which makes collisions practical on long-lived keys (Sweet32) |
| **RSA-1_5** key transport | `acceptedKeyEncryptionMethods` | PKCS#1 v1.5 is Bleichenbacher-attackable. There is no fake-session-key continuation here, so an unwrap failure returns sooner than a success, and a caller who can feed your client chosen ciphertexts can recover the session key and with it one message's plaintext (CVE-2015-0226). Prefer RSA-OAEP; a peer that only wraps with v1.5 is worth pushing back on |
| **RSA-SHA1**, **DSA-SHA1**, **HMAC-SHA1** signatures | `acceptedSignatureMethods` | SHA-1 collisions are practical, and a signature is exactly the place that matters. DSA additionally only works at 1024 bits here, since the `dsa-sha1` URI fixes the coordinate width at 20 bytes. HMAC-SHA1 is what an older `Basic128`-style algorithm suite pins, so a symmetric-binding peer may leave you no choice |
| **HMAC-SHA224** signatures | `acceptedSignatureMethods` | Nothing is wrong with it; it is simply a size nothing emits, and an algorithm no peer asks for is one fewer shape to accept |
| **SHA-1**, **RIPEMD160** digests | `acceptedDigestMethods` | The reference digest is what binds a signature to your body. A collision there is a forged message |
| **Inclusive C14N** (`C14N`, `C14N_COMMENTS`) | `acceptedCanonicalizations` | Not the WS-Security norm, so accepting it only widens what a peer can ask for. Inclusive canonicalization also drags ancestor namespace declarations into the digest, which makes what a signature covers harder to reason about |
| **RSA/DSA keys under 1024 bits**, **EC under 224** | `minimumRsaKeyBits`, `minimumEcKeyBits` | 512-bit RSA is factorable in hours, so the signature proves nothing. Neither the allow-lists nor OpenSSL's path validation constrain key size, so this floor is the only thing that does |

Three things deliberately **not** gated, so you know where the edges are: `Decrypt` never requires a part to
have arrived encrypted, chaining to a trust anchor is not the same as authenticating your peer (see
[Chain validity is not authentication](trust.md#chain-validity-is-not-authentication)), and a signature keyed by
a wrapped session key authenticates nobody at all (see
[`GeneratedSessionKey`](outbound-blocks.md#symmetric-key-sources)).

## Limits on an inbound message

Every parse rejects a DOCTYPE declaration before any block runs, which removes external entities and entity
expansion as an attack surface. Beyond that the middleware relies on the parser's own default limits: it never
asks for the "huge" parse mode that lifts them: so an inbound response is refused once it nests deeper than
256 elements.

Note what that does **not** cover: the parser does not bound the length of an individual text node, and there
is deliberately no total message-size cap here. The response body is already fully in memory by the time a
PSR-18 middleware sees it, so a cap at this layer would only bound parsing cost against a server you chose to
call. Cap the body at the HTTP client if you need one.

- **References per signature:** a `ds:SignedInfo` may declare at most 32 `ds:Reference` entries. A small
  message declaring an absurd number of references would otherwise amplify canonicalization and digest work
  far beyond its own size, which a size limit could not bound.

