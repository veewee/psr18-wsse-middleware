<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\Xml;

/**
 * The XML namespaces used across the XML-Security engine and the WS-Security profile, backed by their
 * canonical URI. The bag is shared vocabulary and carries no behaviour, so it sits in the generic Xml layer.
 */
enum Namespaces: string
{
    case Wsse = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    case Wsu = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
    case Wsse11 = 'http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd';
    case Ds = 'http://www.w3.org/2000/09/xmldsig#';
    case Xenc = 'http://www.w3.org/2001/04/xmlenc#';
    case Xenc11 = 'http://www.w3.org/2009/xmlenc11#';

    public function prefix(): string
    {
        return match ($this) {
            self::Wsse => 'wsse',
            self::Wsu => 'wsu',
            self::Wsse11 => 'wsse11',
            self::Ds => 'ds',
            self::Xenc => 'xenc',
            self::Xenc11 => 'xenc11',
        };
    }

    /**
     * @return non-empty-string the prefix and colon guarantee it, whatever the local name
     */
    public function qualify(string $localName): string
    {
        return $this->prefix().':'.$localName;
    }
}
