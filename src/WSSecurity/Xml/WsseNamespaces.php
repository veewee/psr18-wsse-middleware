<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml;

use Soap\Psr18WsseMiddleware\Xml\QualifiesNames;
use Soap\Psr18WsseMiddleware\Xml\XmlNamespace;

/**
 * The namespaces WS-Security defines: the security extensions in their 1.0 and 1.1 revisions, and the utility
 * namespace that carries wsu:Id and wsu:Timestamp.
 *
 * They live in this layer rather than beside the XML Signature and XML Encryption namespaces because the engine
 * has no business knowing this specification exists. A query the engine runs under this profile's convention is
 * given the binding it needs along with the query.
 */
enum WsseNamespaces: string implements XmlNamespace
{
    use QualifiesNames;

    case Wsse = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    case Wsu = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
    case Wsse11 = 'http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd';

    public function uri(): string
    {
        return $this->value;
    }

    public function prefix(): string
    {
        return match ($this) {
            self::Wsse => 'wsse',
            self::Wsu => 'wsu',
            self::Wsse11 => 'wsse11',
        };
    }
}
