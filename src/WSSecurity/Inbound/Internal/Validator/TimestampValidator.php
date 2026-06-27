<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Inbound\Internal\Validator;

use Psl\DateTime\Timestamp;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;

/**
 * Runs the three freshness checks on already-parsed instants. The clock skew is applied symmetrically to both
 * the lower and upper bounds so that a small difference between the two peers' clocks does not reject an
 * otherwise valid message in either direction.
 *
 * The window itself must be well formed: a remote peer is untrusted, so an expiry at or before the creation
 * instant is rejected outright rather than allowed to slip through the skew budget. Not expired then guards
 * against a replayed message that is past its stated lifetime. Not older than the maximum age bounds the
 * replay window even when a peer sets an over-generous expiry. Not future-dated rejects a message stamped
 * ahead of the receiver, which would otherwise stay valid for longer than intended.
 *
 * Comparison is by integer second timestamps so sub-second formatting differences never affect the decision.
 */
final class TimestampValidator
{
    /**
     * @throws SecurityFault on any failed check
     */
    public function validate(
        Timestamp $now,
        Timestamp $created,
        Timestamp $expires,
        int $clockSkewSeconds,
        int $maxAgeSeconds,
    ): void {
        $nowSeconds = $now->getSeconds();
        $createdSeconds = $created->getSeconds();
        $expiresSeconds = $expires->getSeconds();

        if ($expiresSeconds <= $createdSeconds) {
            throw SecurityFault::inboundFailure();
        }

        if ($nowSeconds > $expiresSeconds + $clockSkewSeconds) {
            throw SecurityFault::inboundFailure();
        }

        if ($nowSeconds - $createdSeconds > $maxAgeSeconds + $clockSkewSeconds) {
            throw SecurityFault::inboundFailure();
        }

        if ($createdSeconds > $nowSeconds + $clockSkewSeconds) {
            throw SecurityFault::inboundFailure();
        }
    }
}
