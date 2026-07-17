<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo;

use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\DistinguishedName;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\WsSecurityValueType;

/**
 * Resolves an identifier reference (Subject Key Identifier, SHA-1 thumbprint, or issuer DN plus serial) to a
 * single trust store certificate. The identifier the reference names is computed for each anchor through the
 * field extractor and matched; an anchor whose identifier cannot be computed (a CA without a Subject Key
 * Identifier, say) simply does not match rather than aborting the search. The match must be unique: an unknown
 * identifier and an ambiguous one are both refused, so no anchor is ever silently preferred over another.
 */
final class TrustStoreCertificateResolver
{
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
            WsSecurityValueType::X509SubjectKeyIdentifier->value
                => static fn (Certificate $candidate): string => $candidate->info()->subjectKeyIdentifier()->toBase64(),
            WsSecurityValueType::ThumbprintSha1->value
                => static fn (Certificate $candidate): string => $candidate->info()->thumbprintSha1()->toBase64(),
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

        $wantedIssuer = DistinguishedName::fromString($reference->issuerName);

        $matches = array_values(array_filter(
            $trustStore->anchors(),
            static function (Certificate $candidate) use ($wantedIssuer, $reference): bool {
                try {
                    $issuerSerial = $candidate->info()->issuerSerial();
                } catch (CryptoOperationFailed) {
                    return false;
                }

                return $issuerSerial->serialNumber->toString() === $reference->serialNumber
                    && $issuerSerial->issuer->equals($wantedIssuer);
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
