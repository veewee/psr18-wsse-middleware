<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Exception;

use RuntimeException;

/**
 * Thrown when a header carries a construct the canonicalizer refuses rather than guesses at.
 *
 * The constructs below need a decoder whose output has to agree with the peer's byte for byte, and nothing
 * short of a message from that peer proves it does. A refusal cannot produce a wrong digest; a guess can,
 * and a wrong digest is the failure mode with no diagnostic attached.
 *
 * Outbound this is a configuration error the caller fixes by simplifying a header. Inbound it collapses
 * into the uniform verification failure like anything else, so it tells a peer nothing.
 */
final class UnsupportedAttachmentHeaderForm extends RuntimeException
{
    /**
     * Canonicalization has no defined answer for two of the same header, and a peer's sorted map silently
     * keeps one of them, so agreeing on a digest would be luck rather than correctness.
     */
    public static function duplicate(string $header, int $count): self
    {
        return new self(sprintf(
            'The attachment header "%s" appears %d times, and at most one is supported.',
            $header,
            $count
        ));
    }

    /**
     * A peer strips the whitespace a MIME parser leaves after the colon from every one of these headers
     * except this one, so what it digests for a Content-Description depends on whether its own parser
     * trimmed the separator. Nothing this side can compute predicts that.
     */
    public static function contentDescription(): self
    {
        return new self(
            'The attachment header "Content-Description" is the one header a peer canonicalizes without '
            .'stripping its leading whitespace, so a digest over it is not reproducible. Remove it from the '
            .'attachment to cover the part completely.'
        );
    }

    public static function comment(string $header): self
    {
        return new self(sprintf('The attachment header "%s" carries a comment, which is not supported.', $header));
    }


    public static function continuedParameter(string $header): self
    {
        return new self(sprintf(
            'The attachment header "%s" carries a continued or charset-tagged parameter, which is not supported.',
            $header
        ));
    }

    public static function unreadableParameter(string $header): self
    {
        return new self(sprintf('The attachment header "%s" carries a parameter this cannot read.', $header));
    }
}
