<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification;

use Dom\Element;
use Soap\Psr18WsseMiddleware\OpenSSL\CertificateFieldExtractor;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Trust\CertificateChain;
use Soap\Psr18WsseMiddleware\WSSecurity\Trust\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\ChildElements;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespace;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdResolver;
use VeeWee\Xml\Dom\Document;

/**
 * Reads the signer's certificate from ds:KeyInfo. Two inbound forms carry the certificate inside the message: a
 * direct BST reference (wsse:SecurityTokenReference > wsse:Reference pointing at a wsse:BinarySecurityToken) and
 * an inline ds:X509Data > ds:X509Certificate. A third group names the certificate by identifier without carrying
 * it: a wsse:KeyIdentifier holding a Subject Key Identifier or a SHA-1 thumbprint, or a ds:X509IssuerSerial.
 * Those references are resolved by matching the identifier against the trust store the caller already holds.
 *
 * Resolving by identifier requires the actual certificate to be available locally, since the message carries
 * only a pointer to it. The trust store is the only local source of candidate certificates, so an identifier
 * that does not match any trust store entry cannot be resolved and is refused. That mirrors how conformant
 * verifiers require the certificate to live in a local store before an identifier reference can name it; a
 * trust store holding only a CA, not the signer leaf, cannot satisfy such a reference.
 *
 * The returned chain is not yet trusted; establishing trust is a separate step. A certificate resolved from the
 * trust store still flows through that step unchanged.
 */
final class CertificateExtractor
{
    private const X509V3_VALUE_TYPE
        = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3';
    private const BASE64_BINARY_ENCODING_TYPE
        = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary';
    private const SUBJECT_KEY_IDENTIFIER_VALUE_TYPE
        = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier';
    private const THUMBPRINT_SHA1_VALUE_TYPE
        = 'http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1';

    public function __construct(
        private CertificateFieldExtractor $fieldExtractor,
    ) {
    }

    /**
     * @throws SignatureVerificationFailed when ds:KeyInfo is absent or carries an unsupported or malformed
     *         certificate reference, or names a certificate the trust store does not hold
     */
    public function extract(Document $document, Element $signatureElement, TrustStore $trustStore): CertificateChain
    {
        $keyInfo = $this->onlyChild($signatureElement, WsseNamespace::Ds, 'KeyInfo');
        if ($keyInfo === null) {
            throw SignatureVerificationFailed::withReason('ds:KeyInfo is missing.');
        }

        $carried = $this->fromSecurityTokenReference($document, $keyInfo)
            ?? $this->fromInlineX509($keyInfo);
        if ($carried !== null) {
            return CertificateChain::fromCertificates($this->certificateFromBase64Der($carried));
        }

        $resolved = $this->fromIdentifierReference($keyInfo, $trustStore);
        if ($resolved !== null) {
            return CertificateChain::fromCertificates($resolved);
        }

        throw SignatureVerificationFailed::withReason(
            'ds:KeyInfo does not carry the certificate in a supported form.',
        );
    }

    /**
     * Resolves a wsse:SecurityTokenReference > wsse:Reference to its wsse:BinarySecurityToken and returns the
     * token's base64 body. Returns null when KeyInfo carries no wsse:Reference at all (so an identifier form or
     * the inline form can be tried), but refuses an unsupported reference shape outright.
     */
    private function fromSecurityTokenReference(Document $document, Element $keyInfo): ?string
    {
        $str = $this->onlyChild($keyInfo, WsseNamespace::Wsse, 'SecurityTokenReference');
        if ($str === null) {
            return null;
        }

        $reference = $this->onlyChild($str, WsseNamespace::Wsse, 'Reference');
        if ($reference === null) {
            // No direct reference: the certificate is not carried by a BST here. The identifier forms are tried
            // by the caller; this method only owns the carried-by-BST path.
            return null;
        }

        $uri = (string) $reference->getAttribute('URI');
        if (!str_starts_with($uri, '#') || $uri === '#') {
            throw SignatureVerificationFailed::withReason('The token reference URI is not a same-document id.');
        }

        $tokenId = substr($uri, 1);

        try {
            $token = WsuIdResolver::resolve($document, $tokenId);
        } catch (IdReferenceException) {
            throw SignatureVerificationFailed::withReason('The referenced security token was not found.');
        }

        if ($token->localName !== 'BinarySecurityToken' || $token->namespaceURI !== WsseNamespace::Wsse->value) {
            throw SignatureVerificationFailed::withReason('The token reference does not point at a BinarySecurityToken.');
        }

        if ($token->getAttribute('ValueType') !== self::X509V3_VALUE_TYPE) {
            throw SignatureVerificationFailed::withReason('The BinarySecurityToken value type is unsupported.');
        }

        // The encoding type is optional and defaults to base64; a present declaration must name that encoding,
        // since the token body is read as base64 regardless. An absent declaration is the conformant default.
        if ($token->hasAttribute('EncodingType')
            && $token->getAttribute('EncodingType') !== self::BASE64_BINARY_ENCODING_TYPE
        ) {
            throw SignatureVerificationFailed::withReason('The BinarySecurityToken encoding type is unsupported.');
        }

        return trim((string) $token->textContent);
    }

    /**
     * Reads an inline ds:X509Data > ds:X509Certificate. Returns null when KeyInfo carries no ds:X509Data so the
     * caller can try an identifier form or refuse with a uniform message.
     */
    private function fromInlineX509(Element $keyInfo): ?string
    {
        $x509Data = $this->onlyChild($keyInfo, WsseNamespace::Ds, 'X509Data');
        if ($x509Data === null) {
            return null;
        }

        $certificate = $this->onlyChild($x509Data, WsseNamespace::Ds, 'X509Certificate');
        if ($certificate === null) {
            return null;
        }

        return trim((string) $certificate->textContent);
    }

    /**
     * Resolves a reference that names the certificate by identifier (Subject Key Identifier, SHA-1 thumbprint, or
     * issuer DN plus serial) against the trust store. Returns null when KeyInfo carries no identifier reference
     * so the caller can refuse with a uniform message. Requires exactly one matching trust store certificate.
     */
    private function fromIdentifierReference(Element $keyInfo, TrustStore $trustStore): ?Certificate
    {
        $str = $this->onlyChild($keyInfo, WsseNamespace::Wsse, 'SecurityTokenReference');
        if ($str === null) {
            return null;
        }

        $keyIdentifier = $this->onlyKeyIdentifier($str);
        if ($keyIdentifier !== null) {
            return $this->resolveByKeyIdentifier($keyIdentifier, $trustStore);
        }

        $issuerSerial = $this->issuerSerialReference($str);
        if ($issuerSerial !== null) {
            return $this->resolveByIssuerSerial($issuerSerial, $trustStore);
        }

        return null;
    }

    /**
     * Reads the at-most-one wsse:KeyIdentifier child. The element lives in either the WSSE 1.0 or the WSSE 1.1
     * namespace depending on the ValueType, so both are accepted but only one may be present.
     */
    private function onlyKeyIdentifier(Element $str): ?Element
    {
        $wsse = $this->onlyChild($str, WsseNamespace::Wsse, 'KeyIdentifier');
        $wsse11 = $this->onlyChild($str, WsseNamespace::Wsse11, 'KeyIdentifier');

        if ($wsse !== null && $wsse11 !== null) {
            throw SignatureVerificationFailed::withReason('wsse:KeyIdentifier must appear at most once in its parent.');
        }

        return $wsse ?? $wsse11;
    }

    private function resolveByKeyIdentifier(Element $keyIdentifier, TrustStore $trustStore): Certificate
    {
        $valueType = $keyIdentifier->getAttribute('ValueType');
        $reference = trim((string) $keyIdentifier->textContent);
        if ($reference === '') {
            throw SignatureVerificationFailed::withReason('The key identifier is empty.');
        }

        $identifierOf = match ($valueType) {
            self::SUBJECT_KEY_IDENTIFIER_VALUE_TYPE => $this->fieldExtractor->subjectKeyIdentifier(...),
            self::THUMBPRINT_SHA1_VALUE_TYPE => $this->fieldExtractor->thumbprintSha1(...),
            default => throw SignatureVerificationFailed::withReason('The key identifier value type is unsupported.'),
        };

        return $this->uniqueMatch(
            $trustStore,
            static fn (string $candidate): bool => $candidate === $reference,
            $identifierOf,
        );
    }

    /**
     * Reads a ds:X509Data > ds:X509IssuerSerial reference into its issuer DN and decimal serial. Returns null
     * when no such reference is present.
     *
     * @return array{issuerName: string, serialNumber: string}|null
     */
    private function issuerSerialReference(Element $str): ?array
    {
        $x509Data = $this->onlyChild($str, WsseNamespace::Ds, 'X509Data');
        if ($x509Data === null) {
            return null;
        }

        $issuerSerial = $this->onlyChild($x509Data, WsseNamespace::Ds, 'X509IssuerSerial');
        if ($issuerSerial === null) {
            return null;
        }

        $issuerName = $this->onlyChild($issuerSerial, WsseNamespace::Ds, 'X509IssuerName');
        $serialNumber = $this->onlyChild($issuerSerial, WsseNamespace::Ds, 'X509SerialNumber');
        if ($issuerName === null || $serialNumber === null) {
            throw SignatureVerificationFailed::withReason('The issuer-serial reference is incomplete.');
        }

        return [
            'issuerName' => trim((string) $issuerName->textContent),
            'serialNumber' => trim((string) $serialNumber->textContent),
        ];
    }

    /**
     * @param array{issuerName: string, serialNumber: string} $reference
     */
    private function resolveByIssuerSerial(array $reference, TrustStore $trustStore): Certificate
    {
        if ($reference['issuerName'] === '' || $reference['serialNumber'] === '') {
            throw SignatureVerificationFailed::withReason('The issuer-serial reference is empty.');
        }

        $wantedIssuer = $this->normalizeDistinguishedName($reference['issuerName']);

        $matches = array_values(array_filter(
            $trustStore->anchors(),
            function (Certificate $candidate) use ($wantedIssuer, $reference): bool {
                try {
                    $fields = $this->fieldExtractor->issuerSerial($candidate);
                } catch (CryptoOperationFailed) {
                    return false;
                }

                return $fields['serialNumber'] === $reference['serialNumber']
                    && $this->normalizeDistinguishedName($fields['issuerName']) === $wantedIssuer;
            },
        ));

        return $this->onlyMatch($matches);
    }

    /**
     * Selects the single trust store certificate whose computed identifier matches. Computing the identifier may
     * fail for a candidate that lacks the field (a CA without a Subject Key Identifier, say); such a candidate
     * simply does not match rather than aborting the search.
     *
     * @param callable(string): bool $matches
     * @param callable(Certificate): string $identifierOf
     */
    private function uniqueMatch(TrustStore $trustStore, callable $matches, callable $identifierOf): Certificate
    {
        $found = array_values(array_filter(
            $trustStore->anchors(),
            static function (Certificate $candidate) use ($matches, $identifierOf): bool {
                try {
                    return $matches(trim($identifierOf($candidate)));
                } catch (CryptoOperationFailed) {
                    return false;
                }
            },
        ));

        return $this->onlyMatch($found);
    }

    /**
     * @param list<Certificate> $matches
     */
    private function onlyMatch(array $matches): Certificate
    {
        if ($matches === []) {
            throw SignatureVerificationFailed::withReason('The referenced certificate is not known.');
        }

        if (count($matches) > 1) {
            throw SignatureVerificationFailed::withReason('The certificate reference is ambiguous.');
        }

        return $matches[0];
    }

    /**
     * Normalizes an RFC 2253 distinguished name for robust comparison across implementations that render the
     * same DN with cosmetic differences. The name is split into its relative components on unescaped commas,
     * each component is split into attribute type and value on the first unescaped equals sign, the type is
     * uppercased and the value is whitespace-trimmed and case-folded. The component order is preserved, since
     * RFC 2253 orders relative names most-specific-first and that ordering is significant.
     *
     * This does not decode RFC 2253 hex-encoded values or reorder multi-valued relative names, so two DNs that
     * are equal only after such decoding are treated as different. The forms compared here are produced by the
     * same field extractor on both sides, so those edge cases do not arise in practice.
     */
    private function normalizeDistinguishedName(string $name): string
    {
        $components = preg_split('/(?<!\\\\),/', $name);
        if ($components === false) {
            return $name;
        }

        $normalized = [];
        foreach ($components as $component) {
            $parts = preg_split('/(?<!\\\\)=/', $component, 2);
            if ($parts === false || count($parts) !== 2) {
                $normalized[] = mb_strtolower(trim($component));
                continue;
            }

            $type = strtoupper(trim($parts[0]));
            $value = mb_strtolower(trim($parts[1]));
            $normalized[] = $type.'='.$value;
        }

        return implode(',', $normalized);
    }

    private function certificateFromBase64Der(string $base64Der): Certificate
    {
        $der = base64_decode($base64Der, true);
        if ($der === false || $der === '') {
            throw SignatureVerificationFailed::withReason('The certificate bytes are not valid base64.');
        }

        // The token body is the base64 of a DER certificate; rewrap it as PEM, the form the OpenSSL boundary
        // reads. Malformed bytes are caught later when the certificate is loaded for trust and verification.
        return Certificate::fromBase64Der($base64Der);
    }

    private function onlyChild(Element $parent, WsseNamespace $namespace, string $localName): ?Element
    {
        $matches = ChildElements::named($parent, $namespace, $localName);
        if (count($matches) > 1) {
            throw SignatureVerificationFailed::withReason(
                sprintf('%s must appear at most once in its parent.', $localName),
            );
        }

        return $matches[0] ?? null;
    }
}
