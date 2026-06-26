<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Trust;

use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;

/**
 * The set of trust anchors / pinned certificates the inbound verifier is willing to accept. A credential
 * value object with no openssl here; the chain validation against these anchors lives in OpenSSL\CertificateTrust.
 */
final class TrustStore
{
    /** @var list<Certificate> */
    private readonly array $anchors;

    private function __construct(Certificate ...$anchors)
    {
        $this->anchors = array_values($anchors);
    }

    public static function fromCertificates(Certificate ...$anchors): self
    {
        return new self(...$anchors);
    }

    /**
     * @return list<Certificate>
     */
    public function anchors(): array
    {
        return $this->anchors;
    }

    public function isEmpty(): bool
    {
        return $this->anchors === [];
    }
}
