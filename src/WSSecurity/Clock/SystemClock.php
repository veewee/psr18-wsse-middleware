<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Clock;

use DateTimeImmutable;
use DateTimeZone;

/**
 * The production clock, reading the system time in UTC.
 */
final class SystemClock implements Clock
{
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('now', new DateTimeZone('UTC'));
    }
}
