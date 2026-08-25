<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\External;

use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;

/**
 * The outcome of sealing a message's external parts: the parts as they now travel, and the id of each
 * xenc:EncryptedData describing them.
 *
 * The ids come back rather than being written into a list the caller owns, so the caller decides how they join
 * the in-document ones in the single ReferenceList. Mirrors SignedExternalParts on the signing side.
 */
final readonly class SealedExternalParts
{
    /**
     * @param list<non-empty-string> $ids
     */
    public function __construct(
        public ExternalPartList $parts,
        public array $ids,
    ) {
    }
}
