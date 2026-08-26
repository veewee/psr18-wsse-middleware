<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization;

use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\CanonicalizationFailed;

/**
 * Forces the apex of a canonical form to declare the empty default namespace, which is what a dereferencing
 * transform's digest input carries.
 *
 * Such a transform pins '#default' in its prefix list, and the emitting side reads that as "state the default
 * namespace on the apex" while also having already accounted for whatever default was in scope. The two
 * together come out as xmlns="" every time: an empty declaration where no default namespace was in scope, and
 * an empty declaration *replacing* the inherited one where there was. The C14N primitive here does neither. It
 * omits the declaration when there is no default to state, and states the inherited value when there is, both
 * of which are the right answer for canonicalization in general and the wrong bytes for this transform.
 *
 * Note what that means for such a reference: the token is digested as though no default namespace applied to
 * it, so the digest does not cover the default namespace the token inherited. That is the transform's
 * behaviour as the peers that emit it implement it, not a choice made here, and reproducing it is the only way
 * to verify what they signed.
 *
 * Applied to a dereferenced reference's canonical form and nowhere else. It is a property of that transform,
 * not of canonicalization, and no other part of the engine goes near it.
 *
 * Getting this wrong fails closed. A wrong declaration changes the digest, and a digest that does not match is
 * a refusal, so an error here cannot become an acceptance.
 */
final class ApexDefaultNamespace
{
    /**
     * @param non-empty-string $canonical
     *
     * @return non-empty-string
     *
     * @throws CanonicalizationFailed when the canonical form does not open with an element start tag, which
     *         no canonicalization of an element produces
     */
    public static function emptied(string $canonical): string
    {
        $name = self::apexName($canonical);
        $rest = substr($canonical, strlen($name));

        // Namespace declarations come first in a canonical start tag and the default one sorts ahead of every
        // prefixed declaration, so an inherited default is always exactly here when it is present at all.
        if (preg_match('/^ xmlns="[^"]*"/', $rest, $declared) === 1) {
            return $name.' xmlns=""'.substr($rest, strlen($declared[0]));
        }

        return $name.' xmlns=""'.$rest;
    }

    /**
     * The opening '<' plus the apex element's qualified name: everything up to the first character that can
     * follow a name in a start tag.
     *
     * @return non-empty-string
     *
     * @throws CanonicalizationFailed
     */
    private static function apexName(string $canonical): string
    {
        if (preg_match('/^<[^\s\/>]+/', $canonical, $matches) !== 1) {
            throw CanonicalizationFailed::apexIsNotAnElement();
        }

        /** @var non-empty-string */
        return $matches[0];
    }
}
