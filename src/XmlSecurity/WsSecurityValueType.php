<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

/**
 * The OASIS WS-Security ValueType URIs that identify what a token or reference carries. Each is a spec
 * identifier with exactly one correct value, written on outbound elements and compared against inbound
 * ones, so a single source of truth removes the risk of a copy diverging into a silent interop break.
 */
enum WsSecurityValueType: string
{
    case X509v3 = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3';
    case X509PKIPathv1 = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509PKIPathv1';
    case X509SubjectKeyIdentifier = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier';
    case ThumbprintSha1 = 'http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1';
    case SamlAssertionId = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID';
    case SamlId = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID';
}
