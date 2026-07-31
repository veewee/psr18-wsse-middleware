# Importing a peer's existing configuration

[← Back to the deep dives](../README.md#deep-dives)

You rarely start from nothing. The service you are integrating with usually has a configuration that already
works somewhere else: a security policy in its own WSDL, a SoapUI project someone tested with, or a set of IBM
WebSphere descriptors the provider sent along. That configuration tells you which blocks you need.

Translating it by hand is possible, and each of the three mappings is long. So they are kept as skills for a
coding agent instead, under `.agents/skills/`:

| Skill | Use it for |
|---|---|
| `wsse-import-wspolicy` | A WS-SecurityPolicy: `sp:` assertions in the WSDL, or a WebSphere policy set's `policy.xml` |
| `wsse-import-soapui` | A `*-soapui-project.xml`, or a SoapUI or ReadyAPI WS-Security panel |
| `wsse-import-ibm` | A `ws-security.xml` or the legacy `ibm-webservices*-ext.xmi` / `-bnd.xmi` descriptors |

Point your agent at the file and ask it to configure the middleware. The skills carry the format details, the
mapping tables, and the rules below.

Start with `wsse-import-wspolicy` when you have a choice. WS-SecurityPolicy is an OASIS standard that Apache
CXF, WSS4J, .NET and WebSphere 7 and later all speak, and it usually needs no extra file because the policy sits
in the WSDL you already have.

## What you get back

A draft. The skills produce the `WsseMiddleware` construction, a note of every argument that departs from the
defaults and which peer setting caused it, a list of anything they could not map, and the steps to verify the
result.

The last two matter more than the first. Several settings in these formats have no counterpart here on purpose,
so a list of open questions is a normal outcome rather than a failure. And the wiring stays a guess until it has
spoken to the peer.

## Rules the translation follows

Worth knowing whether you use a skill or do it yourself.

- **The defaults are the baseline.** Start from `new SecurityProfile()` and change only what the peer's
  configuration forces. A setting that already matches the default does not need writing down.
- **Weakening anything is explicit.** These configurations are old, and often ask for SHA-1, 3DES, AES-CBC or
  RSA-1_5, which the default `CryptoPolicy` refuses. Where a peer forces one, the change carries a comment
  naming the setting that forced it. See [Security profile and defaults](security-profile.md) for why each one
  is refused.
- **Directions get mirrored, not copied.** A SoapUI project is another client's setup, so its outgoing
  configuration is your outbound list. A service's own WebSphere descriptors are the other way round: what they
  require on messages they receive is what you must send.
- **Secrets stay out.** IBM's `{xor}` passwords and SoapUI's plaintext ones are both readable, and neither
  belongs in your code. Reference them the way the rest of your application does.

## Things a translation cannot do for you

- **Supply a keystore password.** Both formats point at JKS or JCEKS files, which this package cannot read, so
  they have to be converted first and every export needs that password. A skill can run the conversion for you,
  but the password itself has to come from you. See
  [converting a Java keystore](key-stores.md#converting-a-java-keystore) for the commands and which of them a
  truststore needs.
- **Replace a Java class.** WebSphere descriptors name `keyLocators` and token handler classes, and some of them
  encode server-side behaviour with no client equivalent.
- **Pick a port for you.** WebSphere scopes settings per port, while a `WsseMiddleware` is configured once per
  client. Two ports that disagree are two middlewares.

## One thing to expect from a WS-SecurityPolicy

Its algorithm suites are older than its reputation suggests. Every standard `sp:AlgorithmSuite` specifies RSA-SHA1
for the signature and AES-CBC for the data, and the `Sha256` in a name like `Basic256Sha256` refers to the digest
only. So a faithful import of even a modern-looking suite asks you to accept algorithms this package refuses by
default, and each one arrives with a comment saying which assertion forced it. That is the intended outcome: see
[Security profile and defaults](security-profile.md) for what is refused and why, and treat the comments as a list
of things to renegotiate with the peer rather than settle for.

## Other sources

A WSS4J setup is usually code rather than a file, so there is nothing to hand over. If you do receive WSS4J
crypto `.properties` files, they hold key material only and say nothing about which parts are protected. Ask for
the WSDL, since the policy in it is the part you actually need.
