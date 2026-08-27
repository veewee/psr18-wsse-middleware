# Rules for importing any WS-Security configuration

Shared by every `wsse-import-*` skill. Read this before mapping anything, whatever the source format. The
sections follow the order you work in: settle the direction, learn the destination, then map under the rules.

## Mirror or copy

Work out which you are doing before you map a single setting.

- The configuration describes **the service you call**: mirror it. What they require on messages they receive
  drives your `outbound` list. What they send back drives your `inbound` list.
- The configuration is **another client's** setup for the same service: copy it. Their outbound is your outbound.

A SoapUI project is almost always the second case. IBM descriptors are usually the first, unless you were given
the `*client*` files. A WS-SecurityPolicy is neither by default: its attachment point decides, so check whether an
assertion sits on the binding, on `wsdl:input` or on `wsdl:output`.

## Know the destination before you map

Read [Outbound blocks](../../docs/outbound-blocks.md), [Inbound blocks](../../docs/inbound-blocks.md) and
[Choosing parts and key references](../../docs/parts-and-key-references.md) before you write any wiring. Not
optional, and not replaceable by reading `src/`: those pages state every argument and every default, and several
defaults are set in places that are easy to miss when skimming code. `Part::body()` selecting
`EncryptionMode::Content` is a constructor default, and mistaking it costs you the difference between encrypting
the Body element and encrypting its content.

Consult these when the mapping reaches them:

- [Security profile and defaults](../../docs/security-profile.md), for what is refused inbound and why
- [Key stores](../../docs/key-stores.md), for loading certificates, keys, PEM bundles and PKCS#12 bundles
- [Trust](../../docs/trust.md), for anchors, pinning and revocation
- [.agents/domain-glossary.md](../domain-glossary.md), for the canonical name of anything you are about to write

## Samples to check yourself against

[`.agents/imports/`](../imports/README.md) holds real configurations published by the stacks these skills read,
under `samples/`: CXF and Metro policies, SoapUI projects with actual Signature and Encryption entries, and
WebSphere's shipped policy sets with their bindings. Every mapping table here was checked against them, and
several were wrong until they were.

It is git-excluded, so on a fresh clone only the tooling is there: `./fetch.sh` inside it brings the samples
back. Reach for it when a source file uses something a table does not cover, when you are about to widen a
mapping, or before changing one of these skills. Its `drafts/` holds the wiring each skill produced for twelve
of the samples, and re-typechecking those is the cheapest way to notice that the package's API moved out from
under a skill.

## The blocks you are mapping onto

An inventory to plan against. The arguments and the `with*()` methods are in the two block pages above; do not
guess them from here.

Outbound, in the order they must run:

| Block | Adds |
|---|---|
| `Timestamp` | A `wsu:Timestamp`, expiring `timestampTtl` seconds out |
| `Username` | A `wsse:UsernameToken`, `PasswordText` by default, `PasswordDigest` or username-only on request |
| `BinarySecurityToken` | An X.509 certificate as a base64-DER token, for the cases a signature does not already embed one. Takes a `Certificate`, so a signing identity goes in as `$clientCertificate->publicCertificate()` |
| `Signature` | A detached multi-reference `ds:Signature` |
| `Encryption` | XML-Enc ciphertext for the named parts, under a fresh session key |
| `SamlAssertion` | A SAML 1.1 or 2.0 assertion obtained elsewhere, imported verbatim |

Inbound, the order mirrors the order the peer applied its protections, so read it off the policy rather than
applying one shape to everything:

| The peer signs then encrypts (the common case, and `sp:SignBeforeEncrypting`) | `Decrypt`, then `VerifySignature`, then `ValidateTimestamp` |
|---|---|
| The peer encrypts then signs (`sp:EncryptBeforeSigning`) | `VerifySignature`, then `Decrypt`, then `ValidateTimestamp` |

Order is behaviour, not style. Inbound has to undo the peer's outermost protection first: where the signature
was made over ciphertext, decrypting first replaces the very nodes the signature covers and a valid response
then fails to verify.

The defaults worth knowing before you write anything, because matching one means writing nothing:

| Setting | Default |
|---|---|
| Signed parts | `[Part::body(), Part::securityHeaderContents()]` |
| Encrypted parts | `[Part::body()]`, in `EncryptionMode::Content` |
| Signing key reference | `KeyRef::BinarySecurityToken` |
| Encryption key reference | `EncKeyRef::SubjectKeyIdentifier` |
| Timestamp TTL, clock skew | 300 seconds, 60 seconds |
| `mustUnderstand` | true |
| Algorithms | RSA-SHA256, SHA-256 digest, exclusive C14N, AES-256-GCM, RSA-OAEP |

## The three rules

1. **Start from the defaults and change only what is forced.** `new SecurityProfile()` is the baseline. If the
   source configuration asks for exactly the defaults above, write nothing. Do not restate a value that already
   matches.

2. **Every downgrade is explicit and says why.** These configurations are old, and routinely name algorithms the
   default `CryptoPolicy` refuses: SHA-1, 3DES, AES-CBC, RSA-1_5, DSA. When a peer forces one, make the change
   and put the source setting in a comment beside it. Never widen an allow-list to make something work without
   saying so in the output.

3. **What you hand over is a draft.** It is unverified until it has spoken to the peer. Say so.

## Unmapped settings are questions

Several settings in these formats have no counterpart here, by design. Java handler classes, JAAS
configurations, Java keystores, server-side trust decisions, arbitrary XPath parts. List each one and ask. Do not
substitute something plausible, and do not quietly drop it.

## Never

- Never write a decoded password, a keystore passphrase or a private key into output or a commit. IBM's `{xor}`
  strings and SoapUI's plaintext `<con:password>` are both readable; that is why they stay out. Reference the
  secret the way the surrounding application does.
- Never invent a `Part` for a keyword you cannot find in the skill's reference. Ask which element is meant.
- Never claim the configuration works. It works when a real exchange says so.

## Verifying

Give these back with the draft, in order:

1. **Typecheck the draft before you hand it over.** Write the wiring to a file and run the project's Psalm over
   it. This is not a style check: the blocks distinguish types that describe the same identity, so a
   `ClientCertificate` where a `Certificate` belongs, or an enum reached under the wrong namespace, is a real
   error a reader will not see in a code block.

   Psalm's own `projectFiles` covers `src` only, so write the draft into `.agents/imports/drafts/` and run
   `vendor/bin/psalm -c .agents/imports/psalm.xml --no-cache`, which reuses the project's autoloader and checks
   your draft alongside the reference ones. Fix what it reports before handing anything over, and say it passed.

   **It proves the shapes, not the invariants.** These blocks guard combinations in their constructors, and a
   clean typecheck says nothing about those: `path:` alongside any `KeyRef` but `BinarySecurityToken` throws, an
   empty `withParts()` list throws, an endorsing `Signature` placed before the block it endorses throws, and a
   session key whose width disagrees with a later block's cipher is refused. So for every pair of arguments you
   are passing together, read the constructor. A draft that typechecks and throws on the first request is worse
   than one that does not compile.

2. **Trace every non-default argument** to a line in the source configuration. One you cannot trace is one you
   invented.
3. **Read the bytes you send.** Check the Security header holds the tokens the peer wants, that the signature
   references cover the parts you expect, and that the key reference is the shape they asked for.
4. **Send one real request.** A peer faulting on a header it cannot understand tells you what no local test can.
5. **Test the inbound side by making it fail.** Inbound failures are uniform by design, so a response that
   passes proves nothing about the inbound list. Confirm it rejects what it should reject, not only that it
   accepts what it should accept.
