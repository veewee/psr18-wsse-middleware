<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\Xml;

use VeeWee\Xml\Dom\Document;
use VeeWee\Xml\Dom\Xpath\Configurator\Configurator;
use function VeeWee\Xml\Dom\Locator\root_namespace_uri;
use function VeeWee\Xml\Dom\Xpath\Configurator\namespaces;

/**
 * Xpath configurator binding the prefixes a query uses. The SOAP root namespace is bound as `soap` from the
 * document itself, which works for both SOAP 1.1 and 1.2; everything else is passed in.
 *
 * The bindings are explicit rather than "every namespace this package knows" so that no layer has to be able to
 * name the specifications above it. A query the engine runs under a profile's id convention is handed that
 * profile's binding along with the query, and the engine never learns what the prefix stands for.
 */
final class Xpath implements Configurator
{
    /**
     * @param array<non-empty-string, non-empty-string> $prefixes prefix => namespace URI, for every prefix the
     *        query uses beyond `soap`
     */
    public function __construct(
        private readonly Document $document,
        private readonly array $prefixes = [],
    ) {
    }

    public function __invoke(\Dom\XPath $xpath): \Dom\XPath
    {
        // `soap` binds to the document's root namespace; dropped for a bare fragment that has none.
        $prefixes = array_filter(['soap' => $this->document->locate(root_namespace_uri())]);

        return namespaces([...$prefixes, ...$this->prefixes])($xpath);
    }
}
