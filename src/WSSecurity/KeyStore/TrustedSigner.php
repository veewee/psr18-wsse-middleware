<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyStore;

use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Metadata\DistinguishedName;

/**
 * The validated signer identity returned to the policy layer after trust establishment succeeds.
 */
final readonly class TrustedSigner
{
    public function __construct(
        private DistinguishedName $subjectDistinguishedName,
        private Certificate $certificate,
    ) {
    }

    public function subjectDistinguishedName(): DistinguishedName
    {
        return $this->subjectDistinguishedName;
    }

    public function certificate(): Certificate
    {
        return $this->certificate;
    }
}
