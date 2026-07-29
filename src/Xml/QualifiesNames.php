<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\Xml;

/**
 * The prefix-and-colon half of XmlNamespace, which is the same wherever the namespace comes from.
 */
trait QualifiesNames
{
    /**
     * @return non-empty-string the prefix and colon guarantee it, whatever the local name
     */
    public function qualify(string $localName): string
    {
        return $this->prefix().':'.$localName;
    }

    /**
     * @return non-empty-string
     */
    abstract public function prefix(): string;
}
