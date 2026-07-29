<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

use Dom\Element;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\CertificateChain;
use Soap\Psr18WsseMiddleware\KeyStore\PkiPath;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\DirectReferenceKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator\BinaryToken;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsSecurityEncodingType;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsSecurityValueType;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespaces;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdConvention;
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
 * The token carries either the certificate alone (#X509v3, the interop default every peer understands) or a
 * whole certification path (#X509PKIPathv1, via forCertificatePath) for a peer that will not complete the chain
 * from its own store and needs the intermediates handed to it.
 *
 * Embedding is idempotent: a token already carrying these bytes is reused rather than duplicated, so a
 * signature and an encryption that both reference the same certificate share one token.
 */
final class BinarySecurityToken implements OutboundAction
{
    private ?CertificateChain $chain = null;

    public function __construct(
        private readonly Certificate $certificate,
    ) {
    }

    /**
     * Carries the chain's whole certification path in one token instead of its leaf alone. The leaf stays the
     * certificate the token stands for: it is the key a signature is verified with, the path is only what a
     * receiver needs to reach a trust anchor.
     */
    public static function forCertificatePath(CertificateChain $chain): self
    {
        $token = new self($chain->leaf());
        $token->chain = $chain;

        return $token;
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
        $header = SecurityHeader::forContext($context);
        $body = $this->body();

        try {
            return $locator->locate($header->element(), $body);
        } catch (WsseHeaderException) {
            $header->appendChildren($this->build($document, $body));

            return $locator->locate($header->element(), $body);
        }
    }

    /**
     * Embeds the token and hands back the key identifier pointing at it. The X.509 interop default both the
     * Signature and the Encryption block reach for.
     *
     * The reference repeats the embedded token's ValueType rather than assuming a bare certificate: the two name
     * the same token, and a receiver that finds them disagreeing refuses the SecurityTokenReference. A path
     * token also has its type named on the reference itself, which is what the X.509 profile asks of a
     * reference to a path and what a bare certificate reference does not carry.
     */
    public function embedAsDirectReference(WsseContext $context): DirectReferenceKeyIdentifier
    {
        $valueType = $this->valueType();

        return new DirectReferenceKeyIdentifier(
            $this->embed($context),
            $valueType->value,
            $this->chain === null ? null : $valueType->value,
        );
    }

    /**
     * The base64 body the token carries: the certification path when one was supplied, the certificate alone
     * otherwise.
     */
    private function body(): string
    {
        return $this->chain === null
            ? $this->certificate->toBase64Der()
            : base64_encode(PkiPath::encode($this->chain));
    }

    private function valueType(): WsSecurityValueType
    {
        return $this->chain === null ? WsSecurityValueType::X509v3 : WsSecurityValueType::X509PKIPathv1;
    }

    /**
     * @return callable(Element): Element
     */
    private function build(Document $document, string $body): callable
    {
        $minter = (new WsuIdConvention())->minter();
        $build = namespaced_element(
            WsseNamespaces::Wsse->value,
            WsseNamespaces::Wsse->qualify('BinarySecurityToken'),
            attribute('ValueType', $this->valueType()->value),
            attribute('EncodingType', WsSecurityEncodingType::Base64Binary->value),
            value($body),
        );

        return static function (Element $parent) use ($build, $minter, $document): Element {
            $element = $build($parent);
            $minter->mint($element, $document);

            return $element;
        };
    }
}
