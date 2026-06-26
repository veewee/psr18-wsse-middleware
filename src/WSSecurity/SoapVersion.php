<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity;

use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Locator\root_namespace_uri;

/**
 * The SOAP version of the message being secured. It determines the envelope namespace that the
 * wsse:Security header's mustUnderstand and actor/role attributes bind to, and the local name of the
 * next-hop targeting attribute (actor in 1.1, role in 1.2). Derived from the envelope at send time,
 * not configured globally, so a single middleware works for both versions.
 */
enum SoapVersion
{
    case Soap11;
    case Soap12;

    private const NS_SOAP11 = 'http://schemas.xmlsoap.org/soap/envelope/';
    private const NS_SOAP12 = 'http://www.w3.org/2003/05/soap-envelope';

    /**
     * The envelope namespace URI: the namespace the mustUnderstand and actor/role attributes live in.
     */
    public function envelopeNamespace(): string
    {
        return match ($this) {
            self::Soap11 => self::NS_SOAP11,
            self::Soap12 => self::NS_SOAP12,
        };
    }

    /**
     * The local name of the next-hop targeting attribute: actor for 1.1, role for 1.2.
     */
    public function actorOrRoleName(): string
    {
        return match ($this) {
            self::Soap11 => 'actor',
            self::Soap12 => 'role',
        };
    }

    /**
     * @throws WsseHeaderException when the document root is neither a SOAP 1.1 nor a SOAP 1.2 envelope
     */
    public static function fromDocument(Document $document): self
    {
        $namespace = $document->locate(root_namespace_uri());

        return match ($namespace) {
            self::NS_SOAP11 => self::Soap11,
            self::NS_SOAP12 => self::Soap12,
            default => throw WsseHeaderException::invalidSoapVersion($namespace ?? ''),
        };
    }
}
