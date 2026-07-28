<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder;

use Dom\Element;
use Dom\XPath;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\Xml\Manipulator\NodeOrder;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\Xml\Query;
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
     * The header for the message in flight, targeted as the profile says. Every outbound block resolves it
     * this way, so the whole list writes into one header, targeted once, instead of each block deciding.
     *
     * @throws WsseHeaderException when the document is not a usable SOAP envelope
     */
    public static function forContext(WsseContext $context): self
    {
        $profile = $context->profile();

        return self::locateOrCreate(
            $context->document(),
            $context->soapVersion(),
            $profile->mustUnderstand(),
            $profile->actorOrRole(),
        );
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

        $envelopeNamespace = $soapVersion->envelopeNamespace();
        // Reuse the envelope's existing prefix for the SOAP-namespaced attributes. A fresh prefix would
        // redeclare the envelope namespace on wsse:Security, a redundant declaration that is dropped on
        // serialisation: inclusive C14N folds it into every descendant digest, so the signed bytes would no
        // longer match the wire and no verifier could reproduce them.
        $ancestorPrefix = $security->lookupPrefix($envelopeNamespace);
        $envelopePrefix = is_string($ancestorPrefix) && $ancestorPrefix !== '' ? $ancestorPrefix : 'soap';

        if ($mustUnderstand) {
            namespaced_attribute($envelopeNamespace, $envelopePrefix.':mustUnderstand', '1')($security);
        }

        if ($actorOrRole !== null) {
            namespaced_attribute(
                $envelopeNamespace,
                $envelopePrefix.':'.$soapVersion->actorOrRoleName(),
                $actorOrRole,
            )($security);
        }

        return new self($security);
    }

    /**
     * Finds the wsse:Security header this receiver must process, returning null when the message carries
     * none. Distinct from locateOrCreate, which mutates the document and stamps targeting attributes.
     *
     * A message may legally carry several Security headers, one per recipient, so only the header targeted
     * at us is ours; a header addressed to any other hop belongs to that hop and is skipped. By default we
     * are the ultimate receiver, whose header is the soap:Header child with no actor/role attribute; a
     * deployment that sits on the path as a named intermediary configures its own actor/role on the profile
     * and its header is the one carrying that exact value. The spec permits at most one such
     * header, and a second one is refused rather than picked: an injected empty header standing in for the
     * real one would expand every dynamic required part to nothing and satisfy the coverage check
     * vacuously. Restricting the lookup to soap:Header children keeps a Security element planted elsewhere
     * in the envelope, notably inside the Body, from being mistaken for the real header.
     *
     * @param string|null $actorOrRole the actor/role whose header is ours; null means the ultimate receiver
     *
     * @throws WsseHeaderException when the message carries more than one header addressed to us
     */
    public static function locate(
        Document $document,
        SoapVersion $soapVersion,
        ?string $actorOrRole = null,
    ): ?Element {
        $attribute = '@soap:'.$soapVersion->actorOrRoleName();
        $addressedToUs = $actorOrRole === null
            ? 'not('.$attribute.')'
            : $attribute.'='.XPath::quote($actorOrRole);

        $ours = Query::elements(
            $document,
            '/soap:Envelope/soap:Header/'.Namespaces::Wsse->qualify('Security').'['.$addressedToUs.']',
        );

        return match ($ours->count()) {
            0 => null,
            1 => $ours->expectSingle(),
            default => throw WsseHeaderException::ambiguousSecurityHeader(),
        };
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
        $existing = Query::elements($document, './'.Namespaces::Wsse->qualify('Security'), $header)->first();

        if ($existing !== null) {
            return $existing;
        }

        $security = namespaced_element(Namespaces::Wsse->value, Namespaces::Wsse->qualify('Security'))($header);
        append($security)($header);

        return $security;
    }
}
