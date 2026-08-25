<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;

/**
 * The external parts one encryption operation seals, plus the two profile facts that apply to all of them: the
 * xenc:EncryptedData/@Type to stamp, and the transform algorithm to declare inside the CipherReference.
 *
 * Both are per-message rather than per-part, which is why they live here instead of on ExternalPart, and why
 * this type exists rather than three more parameters on EncryptionRequest. It carries no store and no key
 * material, so it is a value the profile layer fills in.
 */
final readonly class ExternalPartEncryption
{
    /**
     * @param non-empty-string $type      the xenc:EncryptedData/@Type every sealed part declares
     * @param non-empty-string $transform the ds:Transform algorithm every CipherReference declares
     */
    public function __construct(
        public ExternalPartList $parts,
        public string $type,
        public string $transform,
    ) {
    }
}
