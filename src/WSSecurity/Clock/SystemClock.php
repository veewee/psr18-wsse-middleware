<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Clock;

use Psl\DateTime\Timestamp;

/**
 * The production clock, reading the system time.
 */
final class SystemClock implements Clock
{
    public function now(): Timestamp
    {
        return Timestamp::now();
    }
}
