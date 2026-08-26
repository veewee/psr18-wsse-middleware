<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL;

/**
 * The output of a symmetric encryption: the IV, the raw ciphertext and (GCM only) the authentication tag.
 * A transport struct: the algorithm-specific invariants (GCM 96-bit IV, 128-bit tag, CBC block size) are
 * enforced by Cipher, not here. The XML-Enc CipherValue framing (base64 of IV‖bytes‖tag) is a B5 concern.
 */
final readonly class CipherText
{
    public function __construct(
        public string $iv,
        public string $bytes,
        public ?string $tag = null,
    ) {
    }
}
