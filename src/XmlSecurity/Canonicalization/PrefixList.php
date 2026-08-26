<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization;

use Dom\Element;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Xml\ElementName;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use function VeeWee\Xml\Dom\Locator\Element\children;

/**
 * Reads the exclusive-c14n InclusiveNamespaces PrefixList a canonicalization element carries, split on
 * whitespace. An absent or empty list yields an empty one.
 *
 * The rule lives here rather than beside each reader because more than one place has to agree on it: a
 * ds:CanonicalizationMethod in ds:SignedInfo, a reference's own ds:Transform, and a profile's transform
 * parameters all pin prefixes the same way, and a second implementation of the same parse is a second set of
 * bytes to digest. A duplicate ec:InclusiveNamespaces is refused rather than resolved by taking the first, so
 * an injected sibling cannot decide which prefixes survive into the signed bytes.
 */
final class PrefixList
{
    /**
     * @return list<string>
     *
     * @throws SignatureVerificationFailed when the element carries more than one ec:InclusiveNamespaces
     */
    public static function read(Element $canonicalizationElement): array
    {
        $matches = children($canonicalizationElement)
            ->filter(
                static fn (Element $child): bool => ElementName::matchesUri(
                    $child,
                    SignatureCanonicalization::EXC_C14N->value,
                    'InclusiveNamespaces',
                ),
            );

        if ($matches->count() > 1) {
            throw SignatureVerificationFailed::withReason('ec:InclusiveNamespaces must appear at most once.');
        }

        $inclusiveNamespaces = $matches->first();
        if ($inclusiveNamespaces === null) {
            return [];
        }

        $prefixList = trim((string) $inclusiveNamespaces->getAttribute('PrefixList'));
        if ($prefixList === '') {
            return [];
        }

        return array_values(array_filter(
            preg_split('/\s+/', $prefixList) ?: [],
            static fn (string $prefix): bool => $prefix !== '',
        ));
    }
}
