<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

/**
 * Distinguishes SAML 1.1 from SAML 2.0 within the WSSE assertion block. The two versions differ in
 * namespace URI and in the attribute that carries the assertion's id: SAML 1.1 uses AssertionID in the
 * urn:oasis:names:tc:SAML:1.0:assertion namespace, SAML 2.0 uses ID in urn:oasis:names:tc:SAML:2.0:assertion.
 * The version is caller-supplied because the assertion root alone has no reliable version discriminant.
 */
enum SamlVersion: string
{
    case Saml11 = 'urn:oasis:names:tc:SAML:1.0:assertion';
    case Saml20 = 'urn:oasis:names:tc:SAML:2.0:assertion';

    /**
     * The local name of the attribute carrying the assertion's unique id.
     */
    public function idAttribute(): string
    {
        return match ($this) {
            self::Saml11 => 'AssertionID',
            self::Saml20 => 'ID',
        };
    }
}
