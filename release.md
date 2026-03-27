# v3.0.0

## Breaking changes

- **PHP 8.4+ required** (dropped 8.3)
- **`WsseEntry` interface**: `__invoke()` first parameter changed from `VeeWee\Xml\Dom\Document` to `\DOMDocument`
- **`KeyIdentifier` interface**: `__invoke()` first parameter changed from `VeeWee\Xml\Dom\Document` to `\DOMDocument`
- **`SamlAssertion` constructor**: takes `\DOMDocument` instead of `VeeWee\Xml\Dom\Document`
- **`WssePreset`**: no longer implements veewee/xml's `Configurator` interface; use `WssePreset::xpath(\DOMDocument)` instead
- **Locators** (`SecurityLocator`, `BinaryTokenLocator`, `SignatureLocator`, `EncryptedKeyLocator`): accept `\DOMDocument`, return `\DOMElement`
- **`CustomKeyIdentifier` / `ReferencingKeyIdentifier`**: build nodes via native `\DOMDocument` API (veewee builders removed)
- **`veewee/xml` removed** as a direct dependency (still available transitively via `php-soap/xml`)

## Dependency upgrades

- `php-soap/psr18-transport`: `^1.8` -> `^2.0`
- `php-soap/engine`: `^2.16` -> `^2.20`
- `php-soap/xml`: `^1.9` -> `^1.10`
- `php-http/client-common`: `^2.3` -> `^2.7`
- PSL: replaced `php-standard-library/php-standard-library` with standalone packages (`^6.1`)

## Why the legacy DOM switch?

`robrichards/wse-php` operates on legacy `\DOMDocument`. In veewee/xml v3, the `Document` wrapper shared the same underlying `\DOMDocument`, so it worked transparently. In v4, `Document` wraps `Dom\XMLDocument` (PHP 8.4's new DOM), which has no shared state with legacy DOM. Every bridge requires an XML round-trip. Since all WSSE/WSA operations flow through robrichards, the wrapper added overhead with no benefit. The package now works directly with legacy `\DOMDocument`.

## Upgrading

1. Require PHP 8.4+
2. Custom `WsseEntry` implementations: change `Document $envelope` to `\DOMDocument $envelope`
3. Custom `KeyIdentifier` implementations: change `Document $envelope` to `\DOMDocument $envelope`
4. `SamlAssertion`: pass a `\DOMDocument` instead of `VeeWee\Xml\Dom\Document`
5. If you used `WssePreset` as a veewee `Configurator`: use `WssePreset::xpath($doc)` instead
6. If you read element text via `->nodeValue`: use `->textContent` (new DOM spec)
