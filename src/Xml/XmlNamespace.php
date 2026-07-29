<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\Xml;

/**
 * One XML namespace: its URI and the prefix this package binds it to. Implemented by each layer's own namespace
 * enum, so a helper can name an element in any of them without the generic Xml layer having to know which
 * specifications exist above it.
 */
interface XmlNamespace
{
    /**
     * @return non-empty-string
     */
    public function uri(): string;

    /**
     * @return non-empty-string the prefix XPath queries in this package bind the namespace to
     */
    public function prefix(): string;

    /**
     * @return non-empty-string the prefixed form used when writing an element or attribute name
     */
    public function qualify(string $localName): string;
}
