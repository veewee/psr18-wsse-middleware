<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator\BinaryToken;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Manipulator\WsuIdMinter;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Namespaces;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\attribute;
use function VeeWee\Xml\Dom\Builder\namespaced_element;
use function VeeWee\Xml\Dom\Builder\value;

/**
 * Adds a wsse:BinarySecurityToken carrying the base64-DER form of an X.509 certificate, so the
 * receiver has the public key it needs to verify a signature made with the matching private key. A
 * wsu:Id is minted on the token so a DirectReference key identifier can point a SecurityTokenReference
 * at exactly this token; the block keeps no state, so it is safe to reuse across messages.
 *
 * Embedding is idempotent: a token already carrying this certificate is reused rather than duplicated, so a
 * signature and an encryption that both reference the same certificate share one token.
 */
final class BinarySecurityToken implements OutboundAction
{
    private const VALUE_TYPE_X509V3 = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3';
    private const ENCODING_BASE64 = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary';

    public function __construct(
        private readonly Certificate $certificate,
    ) {
    }

    public function __invoke(WsseContext $context): void
    {
        $this->embed($context);
    }

    /**
     * Ensures the token is present and returns its wsu:Id. An existing token carrying this certificate is
     * reused; only when none is present is a new one appended.
     *
     * @return non-empty-string the token's wsu:Id, without the '#' prefix
     */
    public function embed(WsseContext $context): string
    {
        $document = $context->document();
        $locator = new BinaryToken();

        try {
            return $locator->locate($document, $this->certificate);
        } catch (WsseHeaderException) {
            $header = SecurityHeader::locateOrCreate($document, $context->soapVersion());
            $header->appendChildren($this->build($document, $this->certificate->toBase64Der()));

            return $locator->locate($document, $this->certificate);
        }
    }

    /**
     * @return callable(Element): Element
     */
    private function build(Document $document, string $body): callable
    {
        $minter = new WsuIdMinter();
        $build = namespaced_element(
            Namespaces::Wsse->value,
            Namespaces::Wsse->qualify('BinarySecurityToken'),
            attribute('ValueType', self::VALUE_TYPE_X509V3),
            attribute('EncodingType', self::ENCODING_BASE64),
            value($body),
        );

        return static function (Element $parent) use ($build, $minter, $document): Element {
            $element = $build($parent);
            $minter->mint($element, $document);

            return $element;
        };
    }
}
