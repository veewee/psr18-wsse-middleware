<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL;

use function Psl\SecureRandom\bytes;

/**
 * The single CSPRNG source for keys, IVs and nonces. Centralizing it keeps all random-secret generation
 * inside the OpenSSL\ boundary, where it can be audited in one place.
 */
final class Random
{
    /**
     * @param positive-int $length
     * @return non-empty-string
     */
    public function bytes(int $length): string
    {
        return bytes($length);
    }
}
