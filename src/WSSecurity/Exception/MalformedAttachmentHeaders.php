<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Exception;

use RuntimeException;

/**
 * Thrown when the octets opened out of an attachment's ciphertext do not carry a readable header block.
 *
 * The caps this reports on are a bound rather than a style rule: the bytes are attacker-supplied by the
 * time they are scanned, so a block that never ends would otherwise be scanned to exhaustion. They match
 * what a legitimate peer applies, so a legitimate peer never trips them.
 */
final class MalformedAttachmentHeaders extends RuntimeException
{
    public static function withoutBlankLine(int $maximumHeaders): self
    {
        return new self(sprintf(
            'The opened attachment carries no blank line within its first %d headers.',
            $maximumHeaders
        ));
    }

    public static function lineTooLong(int $maximumLength): self
    {
        return new self(sprintf(
            'The opened attachment carries a header line longer than %d characters.',
            $maximumLength
        ));
    }

    public static function tooManyHeaders(int $maximumHeaders): self
    {
        return new self(sprintf(
            'The opened attachment carries more than %d headers.',
            $maximumHeaders
        ));
    }

    public static function lineWithoutColon(): self
    {
        return new self('The opened attachment carries a header line that carries no colon.');
    }
}
