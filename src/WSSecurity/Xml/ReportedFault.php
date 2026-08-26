<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml;

/**
 * What a peer's soap:Fault stated: its code and its reason, as text fit to put in a log line.
 *
 * Both halves arrive from the response, so this type is the trust boundary for them: the named constructor is
 * the only way in, and it collapses every run of whitespace and control characters to single spaces and caps
 * the length. A value of this type therefore never holds raw peer text, which is what lets the operator log
 * quote it without a caller having to remember to sanitize first.
 *
 * @psalm-immutable
 */
final readonly class ReportedFault
{
    /**
     * The most peer-supplied text worth putting in one log line. Long enough for a real fault reason, short
     * enough that a peer cannot flood the log with one response.
     */
    private const MAX_LENGTH = 200;

    private function __construct(
        public string $code,
        public string $reason,
    ) {
    }

    public static function fromPeer(string $code, string $reason): self
    {
        return new self(self::sanitize($code), self::sanitize($reason));
    }

    /**
     * Control characters become spaces rather than being dropped, so a reason whose words were separated only
     * by a newline does not run together into one token. A truncated value keeps its length at the cap and
     * ends in an ellipsis, so a reader can tell the peer said more.
     */
    private static function sanitize(string $text): string
    {
        $printable = preg_replace('/[\p{C}\s]+/u', replacement: ' ', subject: $text) ?? '';
        $collapsed = trim($printable);

        if (mb_strlen($collapsed) <= self::MAX_LENGTH) {
            return $collapsed;
        }

        return mb_substr($collapsed, start: 0, length: self::MAX_LENGTH - 1).'…';
    }
}
