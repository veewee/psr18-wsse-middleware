<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml;

/**
 * The XML namespaces used throughout the WSSE engine, backed by their canonical URI.
 */
enum WsseNamespace: string
{
    case Wsse = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    case Wsu = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
    case Wsse11 = 'http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd';
    case Ds = 'http://www.w3.org/2000/09/xmldsig#';
    case Xenc = 'http://www.w3.org/2001/04/xmlenc#';

    public function prefix(): string
    {
        return match ($this) {
            self::Wsse => 'wsse',
            self::Wsu => 'wsu',
            self::Wsse11 => 'wsse11',
            self::Ds => 'ds',
            self::Xenc => 'xenc',
        };
    }

    public function qualify(string $localName): string
    {
        return $this->prefix().':'.$localName;
    }
}
