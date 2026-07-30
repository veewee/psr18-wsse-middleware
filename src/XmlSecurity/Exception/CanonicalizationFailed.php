<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Exception;

use Dom\Node;
use RuntimeException;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Throwable;

/**
 * Canonicalization could not produce a usable result. The distinct named constructors record the cause for
 * logging and tests; callers never branch on it, they only know the canonicalization was refused.
 *
 * The emptyOutput case refuses an empty canonicalization: digesting an empty result would enable signature
 * replay, so it must never be signed or compared.
 */
final class CanonicalizationFailed extends RuntimeException
{
    public static function emptyOutput(Node $node, SignatureCanonicalization $method): self
    {
        return new self(sprintf(
            'Canonicalizing <%s> with %s produced an empty result; refusing to sign or digest empty canonical output.',
            (string) $node->nodeName, // psalm's new-Dom stub underspecifies nodeName as mixed; it is a string
            $method->name,
        ));
    }

    public static function excludesEverything(Node $node): self
    {
        return new self(sprintf(
            'Canonicalizing <%s> while excluding it, or an ancestor of it, would leave nothing to digest.',
            (string) $node->nodeName, // psalm's new-Dom stub underspecifies nodeName as mixed; it is a string
        ));
    }

    public static function nativeError(Node $node, SignatureCanonicalization $method, ?Throwable $previous = null): self
    {
        return new self(
            sprintf(
                'Canonicalizing <%s> with %s failed inside libxml.',
                (string) $node->nodeName, // psalm's new-Dom stub underspecifies nodeName as mixed; it is a string
                $method->name,
            ),
            0,
            $previous,
        );
    }
}
