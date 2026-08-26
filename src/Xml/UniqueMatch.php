<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\Xml;

use Dom\Element;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;

/**
 * Resolves a candidate set to the one element it must contain.
 *
 * Nothing found and several found are distinct failures: a duplicate id is the XML Signature Wrapping
 * primitive, so resolving to either candidate would let an attacker pick which element a reference covers.
 * Every id resolution in the codebase reports both through this one helper.
 */
final class UniqueMatch
{
    /**
     * @param list<Element> $matches
     *
     * @throws IdReferenceException when the candidate set does not hold exactly one element
     */
    public static function require(array $matches, string $subject): Element
    {
        return match (count($matches)) {
            0 => throw IdReferenceException::notFound($subject),
            1 => $matches[0],
            default => throw IdReferenceException::ambiguous($subject),
        };
    }
}
