<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Inbound\Internal\Validator;

use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\Internal\Validator\TimestampValidator;

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
        $now = $created->modify('+10 seconds');
        $expires = $created->modify('+300 seconds');

        $this->expectNotToPerformAssertions();
        (new TimestampValidator())->validate($now, $created, $expires, self::SKEW, self::MAX_AGE);
    }

    public function test_an_expired_timestamp_is_rejected(): void
    {
        $created = static::at('2026-01-01T12:00:00Z');
        $expires = $created->modify('+300 seconds');
        $now = $expires->modify('+3600 seconds');

        $this->expectException(SecurityFault::class);
        (new TimestampValidator())->validate($now, $created, $expires, self::SKEW, self::MAX_AGE);
    }

    public function test_an_expiry_at_or_before_creation_is_rejected(): void
    {
        $created = static::at('2026-01-01T12:00:00Z');
        $expires = $created->modify('-1 second');
        $now = $created;

        $this->expectException(SecurityFault::class);
        (new TimestampValidator())->validate($now, $created, $expires, self::SKEW, self::MAX_AGE);
    }

    public function test_expiry_within_the_skew_is_accepted(): void
    {
        $created = static::at('2026-01-01T12:00:00Z');
        $expires = $created->modify('+300 seconds');
        $now = $expires->modify('+59 seconds');

        $this->expectNotToPerformAssertions();
        (new TimestampValidator())->validate($now, $created, $expires, self::SKEW, self::MAX_AGE);
    }

    public function test_expiry_beyond_the_skew_is_rejected(): void
    {
        $created = static::at('2026-01-01T12:00:00Z');
        $expires = $created->modify('+300 seconds');
        $now = $expires->modify('+61 seconds');

        $this->expectException(SecurityFault::class);
        (new TimestampValidator())->validate($now, $created, $expires, self::SKEW, self::MAX_AGE);
    }

    public function test_a_timestamp_older_than_max_age_plus_skew_is_rejected(): void
    {
        $now = static::at('2026-01-01T12:00:00Z');
        $created = $now->modify('-'.(self::MAX_AGE + self::SKEW + 1).' seconds');
        $expires = $now->modify('+3600 seconds');

        $this->expectException(SecurityFault::class);
        (new TimestampValidator())->validate($now, $created, $expires, self::SKEW, self::MAX_AGE);
    }

    public function test_a_created_far_in_the_future_is_rejected(): void
    {
        $now = static::at('2026-01-01T12:00:00Z');
        $created = $now->modify('+61 seconds');
        $expires = $created->modify('+300 seconds');

        $this->expectException(SecurityFault::class);
        (new TimestampValidator())->validate($now, $created, $expires, self::SKEW, self::MAX_AGE);
    }

    public function test_a_created_within_the_future_skew_is_accepted(): void
    {
        $now = static::at('2026-01-01T12:00:00Z');
        $created = $now->modify('+59 seconds');
        $expires = $created->modify('+300 seconds');

        $this->expectNotToPerformAssertions();
        (new TimestampValidator())->validate($now, $created, $expires, self::SKEW, self::MAX_AGE);
    }

    private static function at(string $value): DateTimeImmutable
    {
        return new DateTimeImmutable($value, new DateTimeZone('UTC'));
    }
}
