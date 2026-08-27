<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity;

use InvalidArgumentException;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsSecureConversationVersion;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;

/**
 * The shared-settings value object each block reads through the context. It carries the WS-Security timestamp
 * window (outbound Expires and inbound freshness), how the Security header is targeted and whether a receiver
 * must understand it, and composes the XML-Security algorithm policy that drives signing, encryption and the
 * inbound accept allow-lists. Required by WsseMiddleware; every field has a secure default.
 *
 * The actor/role is one setting doing two jobs, because both answer the same question: which hop this
 * exchange belongs to. Outbound it targets the header we write; inbound it selects the header we read, so a
 * deployment that speaks as a named intermediary is understood in both directions from one value.
 *
 * @psalm-immutable
 */
final class SecurityProfile
{
    private readonly CryptoPolicy $crypto;

    /**
     * @param string|null $actorOrRole the hop this exchange belongs to: soap:actor (SOAP 1.1) or soap:role
     *                                 (SOAP 1.2). Null, the default, means the ultimate receiver, whose header
     *                                 carries no such attribute
     * @param bool        $mustUnderstand whether the outbound Security header demands the receiver process it
     * @param WsSecureConversationVersion $wsSecureConversation which dialect an emitted wsc:DerivedKeyToken is
     *                                 written in. Both are read on the way in whatever this says
     */
    public function __construct(
        private readonly int $timestampTtl = 300,
        private readonly int $clockSkew = 60,
        ?CryptoPolicy $crypto = null,
        private readonly ?string $actorOrRole = null,
        private readonly bool $mustUnderstand = true,
        private readonly WsSecureConversationVersion $wsSecureConversation = WsSecureConversationVersion::V2005_12,
    ) {
        // The window is checked here rather than left to a static-analysis annotation: the TTL also drives the
        // outbound Expires, where a non-positive value would emit a token that expired before it was created.
        if ($timestampTtl < 1) {
            throw new InvalidArgumentException('The timestamp TTL must be a positive number of seconds.');
        }

        if ($clockSkew < 0) {
            throw new InvalidArgumentException('The clock skew must not be negative.');
        }

        $this->crypto = $crypto ?? CryptoPolicy::default();
    }

    public function actorOrRole(): ?string
    {
        return $this->actorOrRole;
    }

    public function mustUnderstand(): bool
    {
        return $this->mustUnderstand;
    }

    public function wsSecureConversation(): WsSecureConversationVersion
    {
        return $this->wsSecureConversation;
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
