<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo;

/**
 * Every reference a signature declares, resolved and split by what it points at.
 *
 * Two lists rather than one, because the two kinds are verified differently and reported differently: an
 * element is re-canonicalized and carried into the result by object identity, for the coverage check that
 * defends against signature wrapping, while an external part is digested as octets and reported by reference.
 * Keeping them apart means neither path can be handed the other's kind by accident.
 */
final readonly class ResolvedReferences
{
    /**
     * @param list<ResolvedVerificationReference> $elements
     * @param list<ResolvedExternalReference>     $external
     */
    public function __construct(
        public array $elements,
        public array $external,
    ) {
    }
}
