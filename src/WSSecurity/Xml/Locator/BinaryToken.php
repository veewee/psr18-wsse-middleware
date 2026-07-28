<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator;

use Dom\Element;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\Xml\ChildElements;
use Soap\Psr18WsseMiddleware\Xml\ElementText;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;

/**
 * Finds the wsse:BinarySecurityToken in a wsse:Security header that carries given bytes and returns its
 * wsu:Id. The match is by content (the token's base64 body equals the expected one, whether that is a single
 * certificate or a whole certification path), so the signature path can reference the token it just embedded
 * without holding on to any minted-id state.
 *
 * The header to search is handed in rather than looked up here: the caller already holds the header it is
 * writing into, and searching only that header keeps a token sitting anywhere else in the envelope from
 * being treated as one of ours.
 */
final class BinaryToken
{
    /**
     * @param string $base64Body the token body to match, as base64 without whitespace
     *
     * @return non-empty-string the matching token's wsu:Id, without the '#' prefix
     *
     * @throws WsseHeaderException when no wsse:BinarySecurityToken in the header carries these bytes
     */
    public function locate(Element $securityHeader, string $base64Body): string
    {
        $expected = Certificate::normalizeBase64Der($base64Body);

        foreach (ChildElements::named($securityHeader, Namespaces::Wsse, 'BinarySecurityToken') as $token) {
            if (Certificate::normalizeBase64Der(ElementText::trimmed($token)) !== $expected) {
                continue;
            }

            $id = $token->getAttributeNS(Namespaces::Wsu->value, 'Id');
            if ($id !== null && $id !== '') {
                return $id;
            }
        }

        throw WsseHeaderException::binaryTokenNotLocatable();
    }
}
