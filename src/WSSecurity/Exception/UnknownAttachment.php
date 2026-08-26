<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Exception;

use RuntimeException;

/**
 * Thrown when a transformed external part names a reference the attachment storage has no attachment for.
 *
 * Outbound this cannot happen without a bug, since the parts handed back are the ones just collected.
 * Inbound it means the engine resolved a reference the storage no longer answers for, so refusing is the
 * only safe move: writing the bytes back under a new id would leave the caller reading an attachment
 * nothing verified.
 */
final class UnknownAttachment extends RuntimeException
{
    public static function forReference(string $reference): self
    {
        return new self(sprintf('No attachment answers the external part reference "%s".', $reference));
    }
}
