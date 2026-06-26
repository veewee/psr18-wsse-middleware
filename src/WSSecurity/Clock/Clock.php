<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Clock;

use DateTimeImmutable;

/**
 * The source of the current instant for the inbound timestamp checks. Those checks assert exact freshness
 * boundaries, so a test must be able to pin "now" to a fixed value while production reads the system clock.
 * The method signature matches the standard clock contract so an external clock can be adopted later without
 * changing any call site.
 */
interface Clock
{
    public function now(): DateTimeImmutable;
}
