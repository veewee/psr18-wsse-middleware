<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo;

use Dom\Element;
use Soap\Psr18WsseMiddleware\Xml\ChildElements;
use Soap\Psr18WsseMiddleware\Xml\ElementText;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdLookup;
use VeeWee\Xml\Dom\Document;

/**
 * The engine's KeyInfoResolver: reads the certificate a plain XML-DSig signature carries inline, as
 * ds:KeyInfo > ds:X509Data > ds:X509Certificate. Nothing here is specific to SOAP or WS-Security, so a caller
 * signing and verifying plain XML needs no configuration.
 *
 * XML-DSig allows more than one ds:X509Certificate so a peer can carry its whole certification path, so all of
 * them are returned in document order -- which says nothing about which is the end-entity, a question answered
 * later from issuer linkage rather than from position.
 */
final class X509DataKeyInfoResolver implements KeyInfoResolver
{
    public function read(Document $document, Element $signatureElement, IdLookup $idLookup): CertificateReference
    {
        $keyInfo = OnlyChild::named($signatureElement, Namespaces::Ds, 'KeyInfo')
            ?? throw SignatureVerificationFailed::withReason('ds:KeyInfo is missing.');

        $carried = $this->inlineCertificates($keyInfo);
        if ($carried === []) {
            throw SignatureVerificationFailed::withReason(
                'ds:KeyInfo does not carry the certificate in a supported form.',
            );
        }

        return CertificateReference::carried(...$carried);
    }

    /**
     * @return list<string>
     */
    private function inlineCertificates(Element $keyInfo): array
    {
        $x509Data = OnlyChild::named($keyInfo, Namespaces::Ds, 'X509Data');
        if ($x509Data === null) {
            return [];
        }

        return array_map(
            static fn (Element $certificate): string => ElementText::trimmed($certificate),
            ChildElements::named($x509Data, Namespaces::Ds, 'X509Certificate'),
        );
    }
}
