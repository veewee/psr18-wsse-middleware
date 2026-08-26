<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Exception;

use RuntimeException;

/**
 * Thrown when a security value that stands in for content elsewhere cannot be restored.
 *
 * The reason never reaches a peer: every one of these leaves as the same uniform SecurityFault, chained for
 * the operator log alone. They are separate messages so an operator can tell a peer whose ids do not match
 * ours apart from a peer sending something malformed, which are different problems to go and fix.
 */
final class OptimizedContentException extends RuntimeException
{
    /**
     * A reference naming nothing the caller supplied.
     *
     * The reference itself is left out. Inbound this is a value a peer chose, and echoing it back into a log
     * line is how a peer gets to decide what that log line says.
     */
    public static function unsuppliedContent(): self
    {
        return new self('A security value points at content that was not supplied.');
    }

    /**
     * A value holding a pointer that is not the whole of its content: text beside it, a second pointer, one
     * nested below a child, or one naming nothing at all.
     *
     * Refused rather than read either way, because whichever reading we picked, the other one is what an
     * attacker would have chosen.
     */
    public static function ambiguousValue(): self
    {
        return new self('A security value describes its content two ways at once.');
    }

    /**
     * More optimized values than the cap allows.
     *
     * A message is small when its content lives in MIME parts, so its own size bounds nothing. Without a
     * count, a tiny envelope could name an unbounded amount of work.
     */
    public static function overCap(): self
    {
        return new self('The message points at more content than it is allowed to.');
    }
}
