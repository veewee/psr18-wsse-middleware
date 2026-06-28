<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification;

use Soap\Psr18WsseMiddleware\OpenSSL\CertificateFieldExtractor;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\OpenSSL\Formatter\DistinguishedName;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Trust\TrustStore;

/**
 * Resolves an identifier reference (Subject Key Identifier, SHA-1 thumbprint, or issuer DN plus serial) to a
 * single trust store certificate. The identifier the reference names is computed for each anchor through the
 * field extractor and matched; an anchor whose identifier cannot be computed (a CA without a Subject Key
 * Identifier, say) simply does not match rather than aborting the search. The match must be unique: an unknown
 * identifier and an ambiguous one are both refused, so no anchor is ever silently preferred over another.
 */
final class TrustStoreCertificateResolver
{
    private const SUBJECT_KEY_IDENTIFIER_VALUE_TYPE
        = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier';
    private const THUMBPRINT_SHA1_VALUE_TYPE
        = 'http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1';

    public function __construct(
        private CertificateFieldExtractor $fieldExtractor,
        private DistinguishedName $distinguishedName = new DistinguishedName(),
    ) {
    }

    /**
     * @throws SignatureVerificationFailed when the reference is unsupported, names no trust store certificate,
     *         or matches more than one
     */
    public function resolve(CertificateReference $reference, TrustStore $trustStore): Certificate
    {
        return match ($reference->form) {
            CertificateReference::FORM_KEY_IDENTIFIER => $this->resolveByKeyIdentifier($reference, $trustStore),
            CertificateReference::FORM_ISSUER_SERIAL => $this->resolveByIssuerSerial($reference, $trustStore),
            default => throw SignatureVerificationFailed::withReason(
                'The certificate reference cannot be resolved against the trust store.',
            ),
        };
    }

    private function resolveByKeyIdentifier(CertificateReference $reference, TrustStore $trustStore): Certificate
    {
        $identifierOf = match ($reference->valueType) {
            self::SUBJECT_KEY_IDENTIFIER_VALUE_TYPE => $this->fieldExtractor->subjectKeyIdentifier(...),
            self::THUMBPRINT_SHA1_VALUE_TYPE => $this->fieldExtractor->thumbprintSha1(...),
            default => throw SignatureVerificationFailed::withReason('The key identifier value type is unsupported.'),
        };

        return $this->uniqueMatch(
            $trustStore,
            static fn (string $candidate): bool => $candidate === $reference->reference,
            $identifierOf,
        );
    }

    private function resolveByIssuerSerial(CertificateReference $reference, TrustStore $trustStore): Certificate
    {
        if ($reference->issuerName === '' || $reference->serialNumber === '') {
            throw SignatureVerificationFailed::withReason('The issuer-serial reference is empty.');
        }

        $wantedIssuer = $this->distinguishedName->normalize($reference->issuerName);

        $matches = array_values(array_filter(
            $trustStore->anchors(),
            function (Certificate $candidate) use ($wantedIssuer, $reference): bool {
                try {
                    $fields = $this->fieldExtractor->issuerSerial($candidate);
                } catch (CryptoOperationFailed) {
                    return false;
                }

                return $fields['serialNumber'] === $reference->serialNumber
                    && $this->distinguishedName->normalize($fields['issuerName']) === $wantedIssuer;
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
}
