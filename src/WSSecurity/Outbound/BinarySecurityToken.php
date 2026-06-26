<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

use Dom\Element;
use LogicException;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Wsse\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\Wsse\WsuIdMinter;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespace;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\attribute;
use function VeeWee\Xml\Dom\Builder\namespaced_element;
use function VeeWee\Xml\Dom\Builder\value;

/**
 * Adds a wsse:BinarySecurityToken carrying the base64-DER form of an X.509 certificate, so the
 * receiver has the public key it needs to verify a signature made with the matching private key. A
 * wsu:Id is minted on the token and exposed through mintedId() so a DirectReference key identifier can
 * point a SecurityTokenReference at exactly this token.
 */
final class BinarySecurityToken implements OutboundAction
{
    private const VALUE_TYPE_X509V3 = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3';
    private const ENCODING_BASE64 = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary';

    /**
     * @var non-empty-string|null
     */
    private ?string $mintedId = null;

    public function __construct(
        private readonly Certificate $certificate,
    ) {
    }

    public function __invoke(WsseContext $context): void
    {
        $document = $context->document();
        $body = $this->base64Der();

        $header = SecurityHeader::locateOrCreate($document, $context->soapVersion());
        $header->appendChildren($this->build($document, $body));
    }

    /**
     * @return non-empty-string the minted wsu:Id, without the '#' prefix
     *
     * @throws LogicException when called before the token has been embedded
     */
    public function mintedId(): string
    {
        if ($this->mintedId === null) {
            throw new LogicException('BinarySecurityToken has no id yet; call __invoke first.');
        }

        return $this->mintedId;
    }

    /**
     * @return callable(Element): Element
     */
    private function build(Document $document, string $body): callable
    {
        $minter = new WsuIdMinter();
        $build = namespaced_element(
            WsseNamespace::Wsse->value,
            WsseNamespace::Wsse->qualify('BinarySecurityToken'),
            attribute('ValueType', self::VALUE_TYPE_X509V3),
            attribute('EncodingType', self::ENCODING_BASE64),
            value($body),
        );

        return function (Element $parent) use ($build, $minter, $document): Element {
            $element = $build($parent);
            $this->mintedId = $minter->mint($element, $document);

            return $element;
        };
    }

    /**
     * @throws WsseHeaderException when the certificate is not decodable PEM
     */
    private function base64Der(): string
    {
        $stripped = preg_replace('/-----[^-]+-----|\s/', '', $this->certificate->contents());
        $der = base64_decode((string) $stripped, true);

        if ($der === false || $der === '') {
            throw WsseHeaderException::bstEncodingFailed('the certificate is not valid base64-encoded PEM');
        }

        return base64_encode($der);
    }
}
