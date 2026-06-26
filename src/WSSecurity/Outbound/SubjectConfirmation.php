<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

/**
 * Declares the subject-confirmation method of the embedded SAML assertion. The block does not parse the
 * assertion's SubjectConfirmation element; this value is caller-supplied metadata describing the assertion's
 * semantics. Holder-of-Key binds a key the caller proves possession of through a separate signature (wired
 * via Outbound\Signature + SamlAssertionKeyIdentifier). Sender-Vouches asserts identity without a separate
 * key proof, so no SamlAssertionKeyIdentifier is needed. The import is identical for either method.
 */
enum SubjectConfirmation
{
    case HolderOfKey;
    case SenderVouches;
}
