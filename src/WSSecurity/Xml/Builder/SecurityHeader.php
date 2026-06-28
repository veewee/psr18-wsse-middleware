<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Manipulator\NodeOrder;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Xpath;
use Soap\Xml\Builder\Header\MustUnderstand;
use Soap\Xml\Builder\SoapHeaders;
use Soap\Xml\Locator\SoapHeaderLocator;
use Soap\Xml\Manipulator\PrependSoapHeaders;
use Throwable;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Assert\assert_element;
use function VeeWee\Xml\Dom\Builder\children;
use function VeeWee\Xml\Dom\Builder\namespaced_attribute;
use function VeeWee\Xml\Dom\Builder\namespaced_element;
use function VeeWee\Xml\Dom\Manipulator\append;

/**
 * The wsse:Security header an outbound message's tokens, signature, and encryption are written into.
 * Locates the single Security element or creates one (adding the soap:Header when the request has
 * none), stamps the mustUnderstand and actor/role targeting attributes, and keeps its children in the
 * canonical order after every append so token builders never have to care about sibling order.
 */
final class SecurityHeader
{
    private function __construct(
        private readonly Element $element,
    ) {
    }

    /**
     * @param string|null $actorOrRole the target for the header: soap:actor (SOAP 1.1) or soap:role
     *                                  (SOAP 1.2); null omits the attribute (targets the ultimate receiver)
     *
     * @throws WsseHeaderException when the document is not a usable SOAP envelope
     */
    public static function locateOrCreate(
        Document $document,
        SoapVersion $soapVersion,
        bool $mustUnderstand = true,
        ?string $actorOrRole = null,
    ): self {
        $header = self::locateOrCreateSoapHeader($document);
        $security = self::locateOrCreateSecurity($document, $header);

        if ($mustUnderstand) {
            (new MustUnderstand())($security);
        }

        if ($actorOrRole !== null) {
            namespaced_attribute(
                $soapVersion->envelopeNamespace(),
                'soap:'.$soapVersion->actorOrRoleName(),
                $actorOrRole,
            )($security);
        }

        return new self($security);
    }

    public function element(): Element
    {
        return $this->element;
    }

    /**
     * Appends token elements to wsse:Security, then re-applies the canonical order so the result is
     * valid regardless of the order the builders were passed in.
     *
     * @param callable(Element): Element ...$builders veewee-style element builders
     */
    public function appendChildren(callable ...$builders): void
    {
        if ($builders === []) {
            return;
        }

        children(...$builders)($this->element);
        NodeOrder::sort($this->element);
    }

    /**
     * @throws WsseHeaderException
     */
    private static function locateOrCreateSoapHeader(Document $document): Element
    {
        $header = $document->locate(new SoapHeaderLocator());
        if ($header !== null) {
            return $header;
        }

        try {
            $created = assert_element($document->build(new SoapHeaders())[0] ?? null);
            $document->manipulate(new PrependSoapHeaders($created));
        } catch (Throwable) {
            throw WsseHeaderException::headerNotLocatable();
        }

        return $created;
    }

    private static function locateOrCreateSecurity(Document $document, Element $header): Element
    {
        $existing = $document
            ->xpath(new Xpath($document))
            ->query('./'.Namespaces::Wsse->qualify('Security'), $header)
            ->expectAllOfType(Element::class)
            ->first();

        if ($existing !== null) {
            return $existing;
        }

        $security = namespaced_element(Namespaces::Wsse->value, Namespaces::Wsse->qualify('Security'))($header);
        append($security)($header);

        return $security;
    }
}
