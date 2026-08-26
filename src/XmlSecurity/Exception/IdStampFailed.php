<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Exception;

use RuntimeException;
use Throwable;

/**
 * An id could not be stamped onto a node, so nothing can reference it. Outbound only: minting happens while a
 * message is being built, never while one is being checked.
 */
final class IdStampFailed extends RuntimeException
{
    public static function becauseOf(Throwable $previous): self
    {
        return new self('Unable to stamp an id onto the node: '.$previous->getMessage(), 0, $previous);
    }
}
