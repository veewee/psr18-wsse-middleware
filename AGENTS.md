# AGENTS.md

Guidance for coding agents working in this repository, following the [agents.md](https://agents.md/) convention.
Human documentation starts at [README.md](README.md).

This is a security package: a PSR-18 middleware that applies WS-Security to SOAP messages. A mistake here does
not produce a visibly broken feature, it produces a message that still sends and protects the wrong thing. Read
before you write, and prefer asking over inferring.

## Getting oriented

| Read | For |
|---|---|
| [README.md](README.md) | How the middleware composes: one `SecurityProfile`, an outbound list, an inbound list |
| [docs/](docs/) | The accurate reference for every block, argument and default. **Use this rather than inferring the API from `src/`** |
| [.agents/domain-glossary.md](.agents/domain-glossary.md) | The canonical term for every concept, with the boundary against neighbouring ones |
| [mago.toml](mago.toml) | The layering contract, self-documenting and enforced |

`docs/` is kept in step with the code deliberately, so that a description of a default is trustworthy. When a
doc page and your reading of `src/` disagree, that is a bug worth reporting, not a reason to trust the code and
move on.

## Commands

`composer.json` declares no scripts. Call the binaries directly, as CI does.

```bash
./vendor/bin/phpunit --fail-on-skipped                          # tests
./vendor/bin/psalm                                              # static analysis
./vendor/bin/mago guard --perimeter                             # architecture layering guard
PHP_CS_FIXER_IGNORE_ENV=1 ./vendor/bin/php-cs-fixer fix         # code style, drop --dry-run to apply
```

Requires PHP `~8.4.21 || ~8.5.0` with `ext-dom`, `ext-intl` and `ext-openssl`. `ext-gmp` or `ext-bcmath` are
optional but make RSA and ECDSA far faster; the CI test job installs both.

## Java interop

Correctness against a real WS-Security stack is proven against Apache WSS4J, not against our own fixtures. A
signature this package considers valid is only interoperable once WSS4J agrees, and a peer's quirk is worth more
than a passing unit test.

The suite lives in [`php-soap/java-interop`](https://github.com/php-soap/java-interop) and runs here through a
reusable workflow, so there is nothing to invoke by hand in CI:

```yaml
# .github/workflows/interop.yml
jobs:
  interop:
    uses: php-soap/java-interop/.github/workflows/interop.yml@main
    with:
      package: php-soap/psr18-wsse-middleware
      suites: wsse
```

It fires on every push to any branch and on every pull request, and it repoints the harness's composer **path
repository** at the commit under test, so the branch is what gets exercised rather than the Packagist release.
`suites` selects which suite runs; this package uses `wsse`, and `attachments` exists for its sibling.

Locally, from a checkout of that repository:

```bash
make interop                      # jar, images, certs, up, test, then always down -v
make interop SUITE=wsse           # or SUITE=attachments
```

It is Docker only, so no host PHP, Java or Maven is needed, and that matters: an older host libxml
canonicalizes differently and has produced a C14N digest mismatch that the container does not.

Two traps that have each cost real time:

- **`make interop` does not rebuild the oracle jar when one exists.** After editing anything under `oracle/`, run
  `make clean` first, or you will exercise the old oracle and draw a confident wrong conclusion from it.
- **Certificates are regenerated per run.** A failure appearing immediately after regeneration, against an oracle
  process still running from before it, is stale state rather than a real break. Rerun once before investigating.
  For the same reason, an expected-byte value pinned from the oracle is true only for that run.

If a change spans both repositories, push both in the same pass rather than leaving the harness local.

Reach for interop when you change signing, verification, encryption, canonicalization or key references. A change
confined to documentation or configuration plumbing does not need it.

## Things that will cost you an hour

- **Read psalm's verdict, not its tail.** Grep for `No errors found!`. The summary reports 100% inference even
  when errors exist above it, and a real error has shipped that way.
- **`mago` is wired only as the architecture guard.** Its formatter, linter and analyzer are deliberately off so
  they never compete with psalm and php-cs-fixer. `mago.toml` is the single source of truth for the internal
  layering: top of the `layering` list is the lowest layer, and a layer may depend on anything below it and
  nothing above. There is exactly one sanctioned upward exception, `KeyStore` reaching `OpenSSL\Parser`. If the
  guard fails, the fix is almost always a misplaced class, not a new permit.
- **psalm ignores `tests/`.** A change to a constructor signature in `src/` therefore breaks test call sites that
  only phpunit will catch. Run both.
- **Some crypto tests skip locally and must not skip in CI.** CI runs `--fail-on-skipped` with `gmp` and
  `bcmath` installed. A local skip is normal; a CI skip is a failure.
- **Trust and inbound failures all share one exception type**, on purpose, so that a peer cannot tell which
  check rejected a message. That makes `expectException(SecurityFault::class)` a vacuous assertion. Assert the
  message, and mutation-check the test by breaking the implementation to confirm it fails.

## Conventions

- **Use the glossary term.** [.agents/domain-glossary.md](.agents/domain-glossary.md) fixes the vocabulary for
  code, comments, documentation and commit messages, and lists what each term must not be called.
- **Write the failing test first** and watch it fail before implementing.
- **Comments explain why, not how.** The code says how. No references to CVEs or other libraries in comments;
  tests carry that context.
- **No em-dashes or en-dashes in prose.** The repository has none; keep it that way.
- **Public API changes update `README.md` and `UPGRADE.md` in the same pass.**
- **Secure defaults are the baseline.** Weakening one is explicit, commented with the reason, and never done to
  make something pass. `docs/security-profile.md` records what is refused and why.

## Skills

Reusable procedures live in `.agents/skills/<name>/SKILL.md`, vendor neutral so any agent can read them. A skill
keeps its knowledge in `docs/` or in its own `references/` directory and stays a thin procedure over it, so that
a person reading the documentation and an agent following the skill work from the same source.

| Skill | Use it when |
|---|---|
| [`wsse-import-wspolicy`](.agents/skills/wsse-import-wspolicy/SKILL.md) | Turning a WS-SecurityPolicy, normally the one in the peer's WSDL, into this package's blocks. The broadest of the three: CXF, WSS4J, .NET and WebSphere 7+ all speak it |
| [`wsse-import-soapui`](.agents/skills/wsse-import-soapui/SKILL.md) | Turning a SoapUI or ReadyAPI WS-Security setup into this package's blocks |
| [`wsse-import-ibm`](.agents/skills/wsse-import-ibm/SKILL.md) | Turning a legacy IBM WebSphere JAX-RPC descriptor into this package's blocks |

Both read [`.agents/references/wsse-import-rules.md`](.agents/references/wsse-import-rules.md), which holds the
rules they share: mirror or copy, defaults as the baseline, explicit downgrades, unmapped settings as questions,
and how the result gets verified. That contract lives in one place rather than being copied into each skill.
[docs/importing-a-peer-configuration.md](docs/importing-a-peer-configuration.md) is the human-facing entry point.
