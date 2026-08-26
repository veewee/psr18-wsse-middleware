<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Exception;

use RuntimeException;

/**
 * Thrown when the installed attachments middleware is too old to re-represent an attachment.
 *
 * The package is a suggestion rather than a requirement, so composer constrains no version and cannot
 * report this. Without the check the miss surfaces as an undefined method from somewhere inside the
 * encryption path, which names neither the package nor the version that would fix it.
 */
final class UnsupportedAttachmentsVersion extends RuntimeException
{
    public static function requiresAtLeast(string $package, string $minimum, string $installed): self
    {
        return new self(sprintf(
            'Attachment security needs %s %s or later to re-represent an attachment; %s is installed.',
            $package,
            $minimum,
            $installed,
        ));
    }
}
