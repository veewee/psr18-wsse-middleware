<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\Xml;

/**
 * The XML namespaces the XML-Security engine works in: XML Signature and XML Encryption. Nothing above these
 * specifications belongs here: a profile carries its own namespaces in its own layer, which is what lets the
 * engine be driven on a document that has no SOAP or WS-Security in it at all.
 */
enum Namespaces: string implements XmlNamespace
{
    use QualifiesNames;

    case Ds = 'http://www.w3.org/2000/09/xmldsig#';
    case Xenc = 'http://www.w3.org/2001/04/xmlenc#';
    case Xenc11 = 'http://www.w3.org/2009/xmlenc11#';

    public function uri(): string
    {
        return $this->value;
    }

    public function prefix(): string
    {
        return match ($this) {
            self::Ds => 'ds',
            self::Xenc => 'xenc',
            self::Xenc11 => 'xenc11',
        };
    }
}
