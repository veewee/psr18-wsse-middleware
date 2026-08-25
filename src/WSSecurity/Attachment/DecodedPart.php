<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Attachment;

use Psl\MIME\Headers;

/**
 * An attachment as it was found inside its own octets: the headers that preceded the blank line, and
 * everything after it.
 */
final readonly class DecodedPart
{
    public function __construct(
        public Headers $headers,
        public string $content,
    ) {
    }
}
