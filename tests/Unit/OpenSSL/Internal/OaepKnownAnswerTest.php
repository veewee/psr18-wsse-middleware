<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\OpenSSL\Internal;

use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use Soap\Psr18WsseMiddleware\OpenSSL\Internal\Oaep;

/**
 * Known-answer tests pinning the deterministic parts of OAEP to fixed expected bytes, so a silent change to
 * MGF1 or to the EME-OAEP decode is caught even if the round trip still happens to agree with itself.
 */
final class OaepKnownAnswerTest extends TestCase
{
    /**
     * MGF1("bar", 50) under SHA-1 is the canonical published mask-generation vector; the SHA-256 counterpart
     * is computed by the same standard construction.
     *
     * @return array<string, array{0: string, 1: int, 2: 'sha1'|'sha256', 3: string}>
     */
    public static function mgf1Provider(): array
    {
        return [
            'sha1-bar-50' => ['bar', 50, 'sha1', 'bc0c655e016bc2931d85a2e675181adcef7f581f76df2739da74faac41627be2f7f415c89e983fd0ce80ced9878641cb4876'],
            'sha256-bar-50' => ['bar', 50, 'sha256', '382576a7841021cc28fc4c0948753fb8312090cea942ea4c4e735d10dc724b155f9f6069f289d61daca0cb814502ef04eae1'],
            'sha1-foo-5' => ['foo', 5, 'sha1', '1ac9075cd4'],
            'sha256-foo-5' => ['foo', 5, 'sha256', '3bdaba83cf'],
        ];
    }

    /**
     * @param 'sha1'|'sha256' $hash
     */
    #[DataProvider('mgf1Provider')]
    public function test_mgf1_matches_known_answer_vectors(string $seed, int $length, string $hash, string $expectedHex): void
    {
        $mgf1 = new ReflectionMethod(Oaep::class, 'mgf1');

        $mask = $mgf1->invoke(null, $seed, $length, $hash);

        static::assertSame($expectedHex, bin2hex($mask));
    }

    /**
     * Decode known-answer test against a frozen vector: a fixed RSA-2048 key and a fixed RSAES-OAEP-SHA256
     * ciphertext, both produced once by the audited phpseclib implementation and pasted in as literals, must
     * decode under our hand-rolled path to the exact known plaintext. Because the ciphertext is captured (not
     * re-randomised here) this pins the decode bytes to an external oracle without a seed knob in production.
     */
    public function test_decode_recovers_a_frozen_phpseclib_sha256_ciphertext(): void
    {
        $privatePem = <<<'PEM'
            -----BEGIN PRIVATE KEY-----
            MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDDdDzLfQI5uWL9
            O/EP92pATk7FCyYfcb2GrrPJ5vXo/xANEhyFVLbEIEyEBoJL1aWBsA/7ws8ZB3KZ
            yN6sYHgH4sAdRcx2KVNhqLPgmglTQEVunUasO8K99gUuuufEC6OOuzUEV/fZWw+U
            me1Lc2gZElGZ7pjlnJMdzZL7EvU0W1JLawkpQtl4ANMoK2KeedZY+Gw1muuZz9ls
            Wcewhbpriq4l3d1zb7hAIFL+LbDBZi0IOU6EDYWiDv7h7ek0zASPJyla34ilS9Ka
            ph1BGTxGT9Y95fOJGBSdZJwFd7d45gfC1OZMiO2R7WXHvBwRpq5I8FifRVBZg8mG
            Si7cKBH7AgMBAAECggEASITMOcP8G2bJb6PZ4U6vQYTMfReR4YDWDS6sznC/NN/O
            GMtrgZzY4xQIz8OKfJCcg+3LQGIbbPHyd1SsKdDxOBvNpA7NudnDciyh8Oe2Jglm
            uY/pNOZHbyvk6F24uGiJGuAi36Wz9BVxRnWGMcR0DzlYxYBdgnQBscEgk7+I8w94
            6zuHkIyECOdzjB08qESH5rwBQRb8FP40amfpQd0MVp/fJjqVHVcTcTXb148ybSh8
            rxXxfjQZ4WsI6Bh3QeDhyu4v1gsAAt5f8A6Gj9yisxZCZzaTLVD5TPWwsehFUueP
            ovi/i7P1x2K/VLQR9qR6BQianngzPFgDlEOauJSlYQKBgQDpIIcd2OW5aLcO5KSs
            Bw+O3BXwe6rxdA3Md2Wap1OAAjbcfkI1WmtYvAlJ8hqtUFvDLLIg7xdANUvEsZoT
            PxO/JFH5gvFZj5Nuozs9SeAJRJsPzUicBcoeESIlBCQVTGgYvL0yrTrQSKC3LXJM
            hKAp7bcieXU4dvIy1LKwNGaE/QKBgQDWoXk4Nb9+P+7iQJHy9unARfitMlVpvro+
            uh6g6PTDZ+S1VU12EbrLfRXt6XfZ6ksJTHzFLyj5L5Bfl/N9alO18WxsvDubSyKx
            uNrdn9ld9sn76Ckr1/2V4Ut1nqXNboO36hV8PXENSmOP/i9LSkB/n7ZfYqKi5ELW
            9DjLjNpgVwKBgARX48yNjvIeXlK7tcmys/qAZTQ+yZeIBv3JN65i8a5P3D/NZmRi
            E9/qWO30wcR628rOGV99tNwwYgH/IRS8txx3i8NvShnWD/QevGrO5oqlqZHozDKD
            9RkMTquL4TQ4YTQcyBWanp7ky4G+KgP88JL3Z9MPmjx8EtUZm16nC0XtAoGADGpU
            x8KcLCJooB/aEXLk/KFPjD1AIZjNzzkW8nnnRrJo0XB4xZ6q7oBy10tNCob6BjSt
            dv6OYTO2J0Fz7UpMQ1cOzY9p50bGX/9wcaeAfGX9Mxwv3YBmA9h/c/NUZfjBl87r
            pT8snfcyoS6z76gA6SEE/KmI/OE1WJfR/TxNmYsCgYEAlexERu0eAjtKrrzuu0g6
            sS2n5mm+bsHR/s5xu7ySu20j+wjQfaYgeJpl4BsG5uvvwxZJRoG1AFPYkaR1zJjo
            OYHkRKW+hnDoNh8tVZCPEuETyAwztY6iGNC3LnFxS5l06jPo0NPAugFY3OOOOtf9
            BZ0O2zmGU7UEhD4s3OG0Jks=
            -----END PRIVATE KEY-----
            PEM;

        $cipherHex = '1b1189ad9e3a78f40468a8b242e2e8c54a71bc33409c03a8919af9cdfc234fda74465f0278606c6966419cd41377c7d3cafbf8dd97553f740fad1ee8ffd11218564b22b1d759522375ade043b9710833619d99c2986b0fb2df6cd29f03c8643653b2022785678b582a64ad599383d1400fc0cc9c752b79ef248f53dd76a4c3aaca44bda4cee94841f7ef9cc5db20d32d670d0babd78cca22a83465ae61a8b5b5d9a706c13cf56d0769f879c4e46061fc8e0e84cc0628008409e522ae17bf8c0ab2569f6a1ff5822206d6d3596e61574ee4dd17d814b289c7436365a6a7385470241b11faed4f056ed75c25198337afa9a8d1bfb7e6faa74657fe60e4276f05ef';
        $expectedPlaintext = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';

        $cipher = hex2bin($cipherHex);
        static::assertIsString($cipher);

        $key = openssl_pkey_get_private($privatePem);
        static::assertInstanceOf(OpenSSLAsymmetricKey::class, $key);

        static::assertSame($expectedPlaintext, bin2hex(Oaep::decode($cipher, $key, 'sha256')));
    }
}
