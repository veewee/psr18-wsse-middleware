<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Attachment;

use Psl\MIME\Headers;
use SensitiveParameter;

/**
 * An attachment as it was found inside its own octets: the headers that preceded the blank line, and
 * everything after it.
 */
final readonly class DecodedPart
{
    /**
     * The content is a file a peer encrypted, so it is kept out of a stack trace the same way every other
     * plaintext on this path is.
     */
    public function __construct(
        public Headers $headers,
        #[SensitiveParameter]
        public string $content,
    ) {
    }
}
