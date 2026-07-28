<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL\Exception;

use RuntimeException;

/**
 * Certificate trust establishment failed. The reasons are descriptive for operator logs; the inbound layer
 * collapses every inbound rejection to one uniform fault before anything reaches a remote peer.
 */
final class CertificateTrustException extends RuntimeException
{
    public static function noTrustAnchors(): self
    {
        return new self('No trust anchors are configured, so no certificate can be trusted.');
    }

    public static function notTrusted(): self
    {
        return new self('The certificate does not chain to a configured trust anchor.');
    }

    public static function expired(): self
    {
        return new self('The certificate is expired or not yet valid.');
    }

    public static function invalidKeyUsage(): self
    {
        return new self('The certificate key usage does not permit digital signatures.');
    }

    public static function unreadable(): self
    {
        return new self('The certificate could not be read.');
    }

    public static function revoked(): self
    {
        return new self('The certificate is listed as revoked.');
    }

    public static function revocationUnknown(): self
    {
        return new self(
            'No supplied revocation list covers the issuer of this certificate, so its revocation state is '
            .'unknown.',
        );
    }

    public static function revocationListStale(): self
    {
        return new self('The revocation list covering this issuer is past its nextUpdate.');
    }

    public static function revocationListUntrusted(): self
    {
        return new self('The revocation list is not signed by a configured trust anchor.');
    }

    public static function revocationListUnreadable(): self
    {
        return new self('The revocation list could not be read.');
    }
}
