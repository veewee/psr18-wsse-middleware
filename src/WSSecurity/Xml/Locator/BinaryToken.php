<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator;

use Dom\Element;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\Xml\ChildElements;
use Soap\Psr18WsseMiddleware\Xml\ElementText;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\Xml\Query;
use VeeWee\Xml\Dom\Document;

/**
 * Finds the wsse:BinarySecurityToken in the wsse:Security header that carries a given certificate and
 * returns its wsu:Id. The match is by content (the token's base64 body equals the certificate's
 * base64-DER form), so the signature path can reference the token it just embedded without holding on to
 * any minted-id state.
 */
final class BinaryToken
{
    /**
     * @return non-empty-string the matching token's wsu:Id, without the '#' prefix
     *
     * @throws WsseHeaderException when no wsse:BinarySecurityToken carries the certificate
     */
    public function locate(Document $document, Certificate $certificate): string
    {
        $expected = $certificate->toBase64Der();

        foreach ($this->securityHeaders($document) as $security) {
            foreach (ChildElements::named($security, Namespaces::Wsse, 'BinarySecurityToken') as $token) {
                if (Certificate::normalizeBase64Der(ElementText::trimmed($token)) !== $expected) {
                    continue;
                }

                $id = $token->getAttributeNS(Namespaces::Wsu->value, 'Id');
                if ($id !== null && $id !== '') {
                    return $id;
                }
            }
        }

        throw WsseHeaderException::binaryTokenNotLocatable();
    }

    /**
     * @return list<Element>
     */
    private function securityHeaders(Document $document): array
    {
        return Query::elements($document, '//'.Namespaces::Wsse->qualify('Security'))
            ->map(static fn (Element $element): Element => $element);
    }
}
