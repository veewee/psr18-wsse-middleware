<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator;

use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\SamlVersion;

/**
 * An assertion found in the Security header: the id a reference points at, and the version that decides how it
 * is named on the wire. The two travel together because a reference carrying one version's ValueType for
 * another version's assertion describes a token the receiver will not find.
 */
final readonly class LocatedSamlAssertion
{
    /**
     * @param non-empty-string $id the assertion's own id, without a '#' prefix
     */
    public function __construct(
        public string $id,
        public SamlVersion $version,
    ) {
    }
}
