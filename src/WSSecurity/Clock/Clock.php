<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Clock;

use Psl\DateTime\Timestamp;

/**
 * The source of the current instant for the inbound timestamp checks. Those checks assert exact freshness
 * boundaries, so a test must be able to pin "now" to a fixed value while production reads the system clock.
 * The instant is returned as a point in time on the epoch, free of any calendar or timezone framing, so the
 * freshness comparison only ever depends on the absolute moment.
 */
interface Clock
{
    public function now(): Timestamp;
}
