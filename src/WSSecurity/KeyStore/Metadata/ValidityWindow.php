<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Metadata;

use Psl\DateTime\Timestamp;

/**
 * The window during which a certificate is valid, so a verifier can reject a not-yet-valid or expired
 * certificate.
 */
final readonly class ValidityWindow
{
    public function __construct(
        public Timestamp $notBefore,
        public Timestamp $notAfter,
    ) {
    }

    public function permits(Timestamp $moment): bool
    {
        return $moment->betweenTimeInclusive($this->notBefore, $this->notAfter);
    }
}
