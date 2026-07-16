<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity;

use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;

/**
 * The shared-settings value object each block reads through the context. It carries the WS-Security timestamp
 * window (outbound Expires and inbound freshness) and composes the XML-Security algorithm policy that drives
 * signing, encryption and the inbound accept allow-lists. Required by WsseMiddleware; every field has a secure
 * default.
 *
 * @psalm-immutable
 */
final class SecurityProfile
{
    private readonly CryptoPolicy $crypto;

    public function __construct(
        private readonly int $timestampTtl = 300,
        private readonly int $clockSkew = 60,
        ?CryptoPolicy $crypto = null,
    ) {
        $this->crypto = $crypto ?? CryptoPolicy::default();
    }

    public static function default(): self
    {
        return new self();
    }

    public function crypto(): CryptoPolicy
    {
        return $this->crypto;
    }

    public function timestampTtl(): int
    {
        return $this->timestampTtl;
    }

    public function clockSkew(): int
    {
        return $this->clockSkew;
    }
}
