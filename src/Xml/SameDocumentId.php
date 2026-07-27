<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\Xml;

/**
 * Reads the id out of a same-document reference URI ("#the-id").
 *
 * Only a same-document reference is accepted: an external URI would let a signature or a data reference point
 * at bytes the message does not carry, and an empty fragment names nothing. Both are reported as null so each
 * caller keeps its own uniform failure.
 */
final class SameDocumentId
{
    /**
     * @return non-empty-string|null the referenced id, or null when the URI is not a same-document reference
     */
    public static function parse(string $uri): ?string
    {
        if (!str_starts_with($uri, '#')) {
            return null;
        }

        $id = substr($uri, 1);

        return $id === '' ? null : $id;
    }
}
