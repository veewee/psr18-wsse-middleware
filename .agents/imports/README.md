# Working material for the import skills

Everything the `wsse-import-*` skills need to be checked against reality, in one place: real configurations
published by the stacks those skills claim to read, the wiring each skill produces for them, and a Psalm config
that typechecks it. Every mapping table in those skills was checked against this, and several were wrong until
they were.

```
imports/
  psalm.xml     typechecks drafts/, because the project's psalm.xml covers src/ only
  fetch.sh      refills samples/ from scratch
  drafts/       the wiring the skills produce, one file per sample
  samples/      third-party configuration files: wspolicy, metro, soapui, ibm
```

**Only the four files at the top are committed.** The samples belong to the projects they came from and carry
their licences; the drafts name real hosts and paths. `.gitignore` excludes the rest, so on a fresh clone
`samples/` and `drafts/` are absent and `./fetch.sh` brings the samples back. It needs `curl` and an
authenticated `gh`, and it overwrites rather than merges.

## Typechecking a draft

Write it into `drafts/` and run, from the repository root:

```
vendor/bin/psalm -c .agents/imports/psalm.xml --no-cache
```

That checks your draft alongside the twelve reference ones, so a green run says both that your wiring compiles
and that the API has not moved under the skills. It is how the `fromEstablishedKeys()` removal was caught.

**It proves the shapes, not the invariants.** These blocks guard combinations in their constructors and a clean
typecheck says nothing about those; read
[the shared rules](../references/wsse-import-rules.md#verifying) before trusting a green result.

`fetch.sh` does not regenerate `drafts/`: those are the output being tested, not input. If they are lost,
re-derive them by running the skills over `samples/`, which is the exercise anyway.

## What the samples cover

| Directory | Source | What it exercises |
|---|---|---|
| `samples/wspolicy/` | `apache/cxf`, `systests/ws-security` | 32 WS-SecurityPolicy files. The `*-policy.xml` are standalone alternatives; the `DoubleIt*.wsdl` show the binding plus `wsdl:input`/`wsdl:output` split, attachments with both `sp13` transforms, symmetric bindings, derived keys, endorsing tokens under both binding kinds |
| `samples/metro/` | `eclipse-ee4j/metro-wsit` | Metro's own idioms: `sc:KeyStore`/`sc:TrustStore` inside a policy, `sp:SamlToken`, `sp:WssX509V1Token10`, the 2005/07 namespace |
| `samples/soapui/` | `RUB-NDS/SOAP-Test-Webservices`, plus three others | Seven projects with real Signature, Encryption and Timestamp entries against Axis2, Metro and CXF. The SmartBear WSTF ones have empty `wssContainer` elements and are kept only as a counter-example |
| `samples/ibm/` | `IBM/webspherelab`, `windup/windup-java-ee-tests` | The shipped WebSphere policy-set library (`policy.xml`) with the cell's general `bindings.xml`, plus the one JAX-RPC `ibm-webservicesclient-ext.xmi` found carrying security config. Other public `.xmi` files are empty stubs and are not fetched |

## What is still missing

- **A SoapUI project using `keyIdentifierType` other than `2`.** All seven carry `2`, so the `1`, `3`, `4`, `8`
  and `12` rows rest on WSS4J's constants and SoapUI's own combo boxes rather than on a file.
- **An IIB or ACE `*.wssecbindings.xml`.** Several public workspace repos have them (code-search
  `ws-securitybinding language:xml`). A related IBM format from a different product, not covered by any skill.
- **An application-scoped WebSphere binding.** Only the cell's general bindings were found, so the
  application-level overlay is unverified.
- **A real WCF or .NET published WSDL.** The `rubnds_WCF-1.xml` project talks to one but carries no security
  configuration of its own, so the `CustomBinding` idioms in the WS-SecurityPolicy skill come from a policy a
  user pasted rather than from a fixture.
