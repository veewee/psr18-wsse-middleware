<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsSecurityValueType;

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

    /**
     * The KeyIdentifier ValueType a reference to an assertion of this version carries. SAML 2.0 has its own,
     * added by the 1.1 profile; the 1.0-profile SAMLAssertionID describes a 1.1 assertion.
     */
    public function keyIdentifierValueType(): WsSecurityValueType
    {
        return match ($this) {
            self::Saml11 => WsSecurityValueType::SamlAssertionId,
            self::Saml20 => WsSecurityValueType::SamlId,
        };
    }

    /**
     * The wsse11:TokenType naming this version, which a reference to a SAML 2.0 assertion must carry and any
     * reference to an assertion should.
     *
     * @return non-empty-string
     */
    public function tokenType(): string
    {
        return match ($this) {
            self::Saml11 => 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1',
            self::Saml20 => 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0',
        };
    }
}
