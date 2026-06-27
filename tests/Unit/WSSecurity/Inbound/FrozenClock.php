<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Inbound;

use Psl\DateTime\Timestamp;
use Soap\Psr18WsseMiddleware\WSSecurity\Clock\Clock;

/**
 * A clock pinned to a fixed instant so timestamp freshness boundaries can be asserted exactly.
 */
final class FrozenClock implements Clock
{
    public function __construct(
        private readonly Timestamp $now,
    ) {
    }

    public function now(): Timestamp
    {
        return $this->now;
    }
}
