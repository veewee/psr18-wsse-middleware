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
     *
     * @return non-empty-string
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
     * The reserved actor/role values a receiver must treat as addressed to itself, alongside the absent
     * attribute that names the ultimate receiver implicitly.
     *
     * SOAP 1.2 role/next targets every node on the path, and the ultimate receiver is one of them; role/
     * ultimateReceiver names it outright. SOAP 1.1 actor/next is the same idea: for a client reading a
     * response, the next node is this one. A peer that spells any of them out is addressing us conformantly,
     * so refusing the header for carrying one would reject a correct message.
     *
     * role/none is deliberately absent: it means no node processes the header, so it is never ours.
     *
     * @return list<non-empty-string>
     */
    public function reservedSelfTargets(): array
    {
        return match ($this) {
            self::Soap11 => ['http://schemas.xmlsoap.org/soap/actor/next'],
            self::Soap12 => [
                'http://www.w3.org/2003/05/soap-envelope/role/next',
                'http://www.w3.org/2003/05/soap-envelope/role/ultimateReceiver',
            ],
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
