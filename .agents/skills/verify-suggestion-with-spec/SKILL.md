---
name: verify-suggestion-with-spec
description: Use when triaging a code-review finding, PR comment, audit report or AI-generated review claim about this package before acting on it — deciding fix-vs-rebut, working through a batch of review findings, or checking any claim about WS-Security / XML-DSig / XML-Enc conformance, crypto behaviour, or "nothing checks X".
---

# Verify a Suggestion Against the Spec

## Overview

A review finding is a **hypothesis with citations**, not a defect. Reviewers — human and AI — routinely produce findings that read as airtight and are wrong, because the reviewer could not execute the code, could not read `vendor/`, or searched a smaller surface than the claim covers.

**Core principle: a finding is not real until you have reproduced its evidence yourself.** Fixing an unreal finding costs a wrong code change plus a test that pins it forever. Rebutting a real one ships a security bug.

Your output is a **disposition per finding**, not a patch.

## The Iron Law

```
NO DISPOSITION WITHOUT REPRODUCED EVIDENCE
```

If you cannot reproduce a finding's evidence, its disposition is **UNVERIFIED**, not "probably valid". Say so, and name what would settle it.

**No exceptions:**
- Not for "the reviewer cited exact line numbers" — citations are the hypothesis, not the proof
- Not for "it's obviously true" — the worst false findings read as the most obvious
- Not for "it's only a docs fix" — doc fixes assert facts too

## Step 1 — Get a Runtime

This package requires PHP `~8.4.21 || ~8.5.0`. Most hosts sit below that floor, where `phpunit`, `psalm` and `mago` cannot run. Check first:

```bash
php -v
```

Below `8.4.21`, build the container shipped with this skill:

```bash
docker build -t wsse-verify:8.4 -f .agents/skills/verify-suggestion-with-spec/references/Dockerfile .
docker run --rm -v "$PWD":/app -w /app wsse-verify:8.4 ./vendor/bin/phpunit --fail-on-skipped
```

Run everything else through the same image:

```bash
D="docker run --rm -v $PWD:/app -w /app wsse-verify:8.4"
$D ./vendor/bin/phpunit --fail-on-skipped     # tests; --fail-on-skipped matters, crypto tests are PHP-gated
$D ./vendor/bin/psalm --no-cache              # static analysis
$D ./vendor/bin/mago guard --perimeter        # layering guard
$D php -r 'require "vendor/autoload.php"; /* one-off probe */'
```

Two gotchas that will mislead you:

- **Psalm: read the error count, not the tail.** It prints `Psalm was able to infer types for 100% of the codebase` even when errors exist. Grep for `No errors found!`.
- **The crypto tests are gated `#[RequiresPhp('>= 8.4.21')]`** and skip silently below the floor. Without `--fail-on-skipped` a run on a too-old patch reports green having verified no signing or encryption at all.

A triage that says "I could not run the suite" when this container was one command away is not a triage.

## Step 2 — The Five Checks

Run in order. Stop at the first that settles it.

### 1. Read the cited lines

Open the file. Confirm the code says what the finding quotes. Findings get written against another commit, get line numbers regenerated, or quote a docblock as if it were code.

### 2. Read the dependency — do not reason about it

**Highest-yield check by a wide margin.** If the claim rests on what a library does, open the installed version in `vendor/` and read the function.

For this package that is almost always **phpseclib**, and knowing what actually runs where matters:

| Operation | Actually performed by |
|---|---|
| Symmetric ciphers (AES-GCM/CBC, 3DES) | `phpseclib3\Crypt\{AES,TripleDES}` |
| RSA / ECDSA signature and verification | `phpseclib3\Crypt\PublicKeyLoader` via `src/OpenSSL/Signer.php` |
| RSA key transport (wrap / unwrap) | `phpseclib3` via `src/OpenSSL/KeyTransport.php` |
| CRL parsing | `phpseclib3\File\X509` |
| Digests | native `hash()` — ext-hash |
| Certificate path validation, key and PEM parsing | `ext-openssl` |

So `ext-openssl` performs no signature or cipher operation in this package at all, despite the namespace name. Verify with `grep -rn "openssl_sign\|openssl_verify" src/` — no call sites.

Better than reading, execute it:

```bash
docker run --rm -v "$PWD":/app -w /app wsse-verify:8.4 php -r '
require "vendor/autoload.php";
$x = new phpseclib3\File\X509();
$x->loadCA($twoCertBundle);
// then reflect on the CAs property and count what actually registered
'
```

That probe is how the "only the first trust anchor is registered" finding was confirmed, and how two other findings about phpseclib were refuted.

### 3. Search the whole surface the claim covers

"Nothing in `src/` guards X" is a finding only if nothing *anywhere* guards X. Also check:

- generated code — `vendor/composer/platform_check.php`, and `composer config platform-check`
- toolchain guards — `.github/workflows/`, `mago.toml`, `psalm.xml`, `phpunit.xml`
- the layer above and below the cited one

Narrow-surface search is how a non-defect becomes a HIGH finding.

### 4. Check the governing spec

Normative text beats intuition. In order of authority here:

1. **The OASIS schemas shipped in `resources/xsd/`** — in-repo and unarguable. If the code refuses a shape the shipped XSD declares `minOccurs="0"`, that is a real interop refusal.
2. **OASIS WS-Security 1.1** core, plus the X.509 and SAML token profiles — token references, `wsse11:TokenType`, `ValueType`, `EncodingType`.
3. **W3C XML-Enc 1.1 and XML-DSig** — `xenc11#rsa-oaep` vs the legacy `xmlenc#rsa-oaep-mgf1p`, MGF defaults (an absent `xenc11:MGF` child means MGF1-SHA1), `EncryptedKey`/`ReferenceList` structure, exclusive C14N and `InclusiveNamespaces`.
4. **RFC 5280** for chains and CRLs (`thisUpdate`/`nextUpdate` semantics, CRL numbers), **RFC 4514/2253** for distinguished-name escaping.

Distinguish MUST from SHOULD from silence. A receiver refusing a *legal* shape is an interop bug however defensible it feels — that is the difference between "unusual" and "illegal".

### 5. Check a reference implementation

For interop claims, what a mature peer actually emits beats what the spec permits. **Apache WSS4J** is this package's oracle and it is already wired up: the harness lives in [`php-soap/java-interop`](https://github.com/php-soap/java-interop), runs WSS4J in Docker, and consumes this branch through a Composer path repository. `.github/workflows/interop.yml` runs it on every push and PR.

From a checkout of that repository:

```bash
make interop SUITE=wsse       # jar, images, certs, up, test, then always down -v
```

Two traps that have each cost real time:

- `make interop` does **not** rebuild the oracle jar when one exists. After editing anything under `oracle/`, run `make clean` first, or you will exercise the old oracle and draw a confident wrong conclusion.
- Certificates regenerate per run. A failure appearing right after regeneration, against an oracle process still running from before it, is stale state. Rerun once before investigating. For the same reason a byte value pinned from the oracle is true only for that run.

Reach for interop whenever the claim touches signing, verification, encryption, canonicalization or key references. If this package and WSS4J disagree, that is the finding, whichever way the spec reads.

## Step 3 — Ask Whether It Is In Scope

A verified-real finding can still be the wrong thing to fix. Check the design record before proposing code:

- `AGENTS.md` and `docs/` — `docs/` is deliberately kept in step with the code, so a documented default is meant to be trustworthy. Where a doc page and `src/` disagree, that is a bug worth reporting, not a reason to trust the code.
- `.agents/domain-glossary.md` — the canonical term for each concept and its boundary against neighbours
- the PR body's stated scope, and any blueprint or handoff notes the repository carries

A restriction the design deliberately took is a **documentation defect** when undocumented — not a code defect. Widening the code to close it is scope creep dressed as a fix.

## Disposition Vocabulary

Every finding gets exactly one, including the ones you refuse:

| Disposition | Meaning | Action |
|---|---|---|
| **CODE** | Reproduced; the code is wrong | Fix test-first — watch it fail with the predicted error before implementing |
| **DOC** | Code is right; prose, docblock, README or UPGRADE is wrong | Fix the prose. Public-API changes update `README.md` and `UPGRADE.md` in the same pass |
| **TEST** | Behaviour is right; nothing pins it, or the test that claims to is vacuous | Add or repair the test |
| **BY-DESIGN** | Real limitation, deliberately scoped out | Document the limitation; do not widen |
| **WRONG** | Evidence does not reproduce | Rebut, citing what you read |
| **UNVERIFIED** | Could not reproduce either way | Say so; name what would settle it |

## Writing a Rebuttal

A rebuttal is credible only with the counter-evidence in it. Name the file, the version and the line you read.

> **Not reproduced.** `composer config platform-check` returns `php-only`, and the regenerated `vendor/composer/platform_check.php` contains `if (!(PHP_VERSION_ID >= 80421))`, which throws at autoload. The deploy-drift scenario aborts before any code runs.

Not: "I don't think this is an issue."

State what you did *not* verify too — which runtime you were on, which suite you could not run.

## Common Mistakes

| Mistake | Why it costs you |
|---|---|
| Fixing the batch in severity order without triaging first | You implement the wrong findings first and ship a noisy PR |
| Reading a finding's own `verification: CONFIRMED` as verification | That is the reviewer's confidence in itself, not evidence |
| Accepting a claim about library behaviour | The top source of false findings. Read `vendor/`, or execute a probe |
| Turning a doc defect into a code change | Widens the API to match a sentence that was simply wrong |
| Asserting only the exception class on an inbound test | Trust and inbound failures all share one exception type on purpose, so `expectException(SecurityFault::class)` is vacuous. Assert the message, and mutation-check the test |
| Trusting a `@param non-empty-list` as a guard | A static constraint is not a runtime check. Psalm will call the runtime guard unreachable — that is the finding, not a reason to drop the guard |
| Silently dropping findings you decided against | Every finding gets a stated disposition |
| Rebutting without reading | A wrong rebuttal is worse than a wrong fix — it closes the thread |

## Red Flags — Stop and Verify

- "vendor/ isn't checked out, but presumably…" → check it out, or run a probe in the container
- "Nothing in src/ does X" → you searched one directory
- "This is a spec violation" and you have not opened `resources/xsd/` or the spec
- "This breaks interop" and you have not run the WSS4J harness
- "The test proves it" and you have not checked that the test fails when the behaviour is removed
- A finding whose fix would widen a boundary the design deliberately drew

**All of these mean: run the five checks before writing a line.**

## Real-World Impact

Applied to a 42-finding deep-review of the WSSE engine rewrite (PR #31), three findings did not reproduce:

- Two rested on phpseclib behaviour the reviewer stated it could not check. Its ASN.1 time format is `'D, d M Y H:i:s O'`, so a decoded `nextUpdate` always carries a UTC offset and `strtotime()` never falls back to the server timezone. And `SymmetricKey::setKey()` throws `InconsistentSetupException` once `setKeyLength()` has pinned an explicit length, so a wrong-length session key cannot silently resize the cipher.
- One claimed no runtime guard existed for the PHP floor, having searched only `src/`.

All three were rated HIGH or MEDIUM and read as airtight. Six more were real but by-design, where the right output was a documented limitation rather than the recommended code change.

Running check 2 as an executed probe also found something the review missed entirely: the `DomCanonicalizerTest` regression test named for CVE-2026-7263 stamped a prefixed *non-xmlns* attribute — a shape that passes on PHP 8.4.19 and 8.4.20, both of which corrupt the canonical form for the shape the defect actually concerns.
