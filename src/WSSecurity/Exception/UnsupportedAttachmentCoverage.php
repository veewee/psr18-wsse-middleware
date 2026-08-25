<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Exception;

use RuntimeException;

/**
 * Thrown when a block is handed an adapter whose coverage it does not implement.
 *
 * Outbound only, and a configuration error rather than a message failure: naming what is missing beats a
 * generic refusal, since the caller is choosing a coverage rather than reacting to a peer.
 */
final class UnsupportedAttachmentCoverage extends RuntimeException
{
    public static function outboundEncryption(): self
    {
        return new self(
            'This block encrypts an attachment\'s content only, so it cannot take an adapter that covers a '
            .'part\'s metadata as well. No policy requires the wider one, since a peer validates the coverage '
            .'of a signature and never of an encryption.'
        );
    }
}
