<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Validator;

use PHPUnit\Framework\TestCase;
use Psl\DateTime\Timestamp;
use Psl\DateTime\Timezone;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Validator\TimestampValidator;

/**
 * The TimestampValidator runs the three freshness checks on already-parsed instants, applying the clock skew
 * symmetrically. These tests pin every instant so each boundary is asserted exactly.
 */
final class TimestampValidatorTest extends TestCase
{
    private const SKEW = 60;
    private const MAX_AGE = 300;

    public function test_a_fresh_timestamp_within_the_window_passes(): void
    {
        $created = static::at('2026-01-01T12:00:00Z');
        $now = $created->plusSeconds(10);
        $expires = $created->plusSeconds(300);

        (new TimestampValidator())->validate($now, $created, $expires, self::SKEW, self::MAX_AGE);

        // The same instants past the window are refused, so the pass above came from a real comparison.
        $this->expectException(SecurityFault::class);
        (new TimestampValidator())->validate($expires->plusSeconds(self::SKEW + 1), $created, $expires, self::SKEW, self::MAX_AGE);
    }

    public function test_an_expired_timestamp_is_rejected(): void
    {
        $created = static::at('2026-01-01T12:00:00Z');
        $expires = $created->plusSeconds(300);
        $now = $expires->plusSeconds(3600);

        $this->expectException(SecurityFault::class);
        (new TimestampValidator())->validate($now, $created, $expires, self::SKEW, self::MAX_AGE);
    }

    public function test_an_expiry_at_or_before_creation_is_rejected(): void
    {
        $created = static::at('2026-01-01T12:00:00Z');
        $expires = $created->minusSeconds(1);
        $now = $created;

        $this->expectException(SecurityFault::class);
        (new TimestampValidator())->validate($now, $created, $expires, self::SKEW, self::MAX_AGE);
    }

    public function test_expiry_within_the_skew_is_accepted(): void
    {
        $created = static::at('2026-01-01T12:00:00Z');
        $expires = $created->plusSeconds(300);
        $now = $expires->plusSeconds(59);

        (new TimestampValidator())->validate($now, $created, $expires, self::SKEW, self::MAX_AGE);

        // Two ticks later the same instants cross the skew and are refused: the boundary is live.
        $this->expectException(SecurityFault::class);
        (new TimestampValidator())->validate($now->plusSeconds(2), $created, $expires, self::SKEW, self::MAX_AGE);
    }

    public function test_expiry_beyond_the_skew_is_rejected(): void
    {
        $created = static::at('2026-01-01T12:00:00Z');
        $expires = $created->plusSeconds(300);
        $now = $expires->plusSeconds(61);

        $this->expectException(SecurityFault::class);
        (new TimestampValidator())->validate($now, $created, $expires, self::SKEW, self::MAX_AGE);
    }

    public function test_a_timestamp_older_than_max_age_plus_skew_is_rejected(): void
    {
        $now = static::at('2026-01-01T12:00:00Z');
        $created = $now->minusSeconds(self::MAX_AGE + self::SKEW + 1);
        $expires = $now->plusSeconds(3600);

        $this->expectException(SecurityFault::class);
        (new TimestampValidator())->validate($now, $created, $expires, self::SKEW, self::MAX_AGE);
    }

    public function test_a_created_far_in_the_future_is_rejected(): void
    {
        $now = static::at('2026-01-01T12:00:00Z');
        $created = $now->plusSeconds(61);
        $expires = $created->plusSeconds(300);

        $this->expectException(SecurityFault::class);
        (new TimestampValidator())->validate($now, $created, $expires, self::SKEW, self::MAX_AGE);
    }

    public function test_a_created_within_the_future_skew_is_accepted(): void
    {
        $now = static::at('2026-01-01T12:00:00Z');
        $created = $now->plusSeconds(59);
        $expires = $created->plusSeconds(300);

        (new TimestampValidator())->validate($now, $created, $expires, self::SKEW, self::MAX_AGE);

        // A Created two ticks further into the future crosses the skew and is refused: the boundary is live.
        $this->expectException(SecurityFault::class);
        (new TimestampValidator())->validate($now, $created->plusSeconds(2), $expires, self::SKEW, self::MAX_AGE);
    }

    private static function at(string $value): Timestamp
    {
        return Timestamp::parse($value, "yyyy-MM-dd'T'HH:mm:ss'Z'", Timezone::UTC);
    }
}
