<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml;

use VeeWee\Xml\Dom\Document;
use VeeWee\Xml\Dom\Xpath\Configurator\Configurator;
use function VeeWee\Xml\Dom\Locator\root_namespace_uri;
use function VeeWee\Xml\Dom\Xpath\Configurator\namespaces;

/**
 * Xpath configurator registering the SOAP root namespace (as `soap`) together with the
 * WSSE / WSU / DSig / XML-Enc namespaces. Works for both SOAP 1.1 and 1.2 envelopes.
 */
final class Xpath implements Configurator
{
    public function __construct(
        private readonly Document $document,
    ) {
    }

    public function __invoke(\Dom\XPath $xpath): \Dom\XPath
    {
        // `soap` binds to the document's root namespace; dropped for a bare fragment that has none.
        $prefixes = array_filter(['soap' => $this->document->locate(root_namespace_uri())]);

        // Each WSSE namespace registers under the prefix it declares on the enum, keeping one source of truth.
        foreach (Namespaces::cases() as $namespace) {
            $prefixes[$namespace->prefix()] = $namespace->value;
        }

        return namespaces($prefixes)($xpath);
    }
}
