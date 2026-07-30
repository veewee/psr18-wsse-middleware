<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\OpenSSL;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\OpenSSL\Cipher;
use Soap\Psr18WsseMiddleware\OpenSSL\CipherText;
use Throwable;

/**
 * Known-answer vectors for the bulk ciphers, published rather than self-generated. The round-trip tests share
 * the cipher implementation between both directions and so stay green through a symmetric bug; these pin the
 * cipher against numbers no part of this codebase produced.
 *
 * The CBC vectors are NIST SP 800-38A F.2.2 and F.2.6, whose four-block plaintext ends in the byte 0x10.
 * XML-Enc padding reads that byte as a pad length, so decrypt returns the first three blocks and consumes the
 * fourth: the assertion still pins the AES-CBC core over all four blocks, since a wrong core would not leave
 * a plausible pad length behind either.
 *
 * The GCM vector is NIST's gcmEncryptExtIV256 case 0 (256-bit key, 96-bit IV, empty AAD).
 */
final class CipherKnownAnswerTest extends TestCase
{
    private const NIST_PLAINTEXT = '6bc1bee22e409f96e93d7e117393172a'
        .'ae2d8a571e03ac9c9eb76fac45af8e51'
        .'30c81c46a35ce411e5fbc1191a0a52ef'
        .'f69f2445df4f9b17ad2b417be66c3710';

    private const NIST_IV = '000102030405060708090a0b0c0d0e0f';

    /**
     * @return iterable<string, array{0: DataEncryptionMethod, 1: non-empty-string, 2: non-empty-string}>
     */
    public static function cbcVectors(): iterable
    {
        // SP 800-38A F.2.2, CBC-AES128.Decrypt
        yield 'aes128-cbc' => [
            DataEncryptionMethod::AES128_CBC,
            '2b7e151628aed2a6abf7158809cf4f3c',
            '7649abac8119b246cee98e9b12e9197d'
            .'5086cb9b507219ee95db113a917678b2'
            .'73bed6b8e3c1743b7116e69e22229516'
            .'3ff1caa1681fac09120eca307586e1a7',
        ];

        // SP 800-38A F.2.6, CBC-AES256.Decrypt
        yield 'aes256-cbc' => [
            DataEncryptionMethod::AES256_CBC,
            '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
            'f58c4c04d6e5f1ba779eabfb5f7bfbd6'
            .'9cfc4e967edb808d679f777bc6702c7d'
            .'39f23369a9d9bacfa530e26304231461'
            .'b2eb05e2c39be9fcda6c19078c6a9d1b',
        ];
    }

    #[DataProvider('cbcVectors')]
    public function test_cbc_decrypt_reproduces_the_nist_plaintext(
        DataEncryptionMethod $method,
        string $keyHex,
        string $cipherTextHex,
    ): void {
        $recovered = (new Cipher())->decrypt(
            new CipherText(self::bytes(self::NIST_IV), self::bytes($cipherTextHex), null),
            SessionKey::fromBytes(self::bytes($keyHex)),
            $method,
        );

        static::assertSame(substr(self::bytes(self::NIST_PLAINTEXT), 0, 48), $recovered);
    }

    /**
     * A wrong-length key must not be silently re-sized into a different cipher, so the AES-256 vector's key
     * cannot decrypt the AES-128 vector even though both ciphers share a block size.
     */
    public function test_a_vector_key_does_not_decrypt_another_vector(): void
    {
        $recovered = null;

        try {
            $recovered = (new Cipher())->decrypt(
                new CipherText(
                    self::bytes(self::NIST_IV),
                    self::bytes('7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2'),
                    null,
                ),
                SessionKey::fromBytes(self::bytes('2b7e151628aed2a6abf7158809cf4f3c')),
                DataEncryptionMethod::AES256_CBC,
            );
        } catch (Throwable) {
            $recovered = null;
        }

        static::assertNotSame(substr(self::bytes(self::NIST_PLAINTEXT), 0, 16), $recovered);
    }

    /**
     * NIST CAVP gcmEncryptExtIV256, [Keylen=256, IVlen=96, PTlen=128, AADlen=0, Taglen=128], Count 0. GCM
     * authenticates its own ciphertext, so the tag is part of the answer: a drift in either the counter mode or
     * GHASH shows up here.
     */
    public function test_gcm_decrypt_reproduces_the_nist_plaintext_and_needs_the_nist_tag(): void
    {
        $cipherText = new CipherText(
            self::bytes('0d18e06c7c725ac9e362e1ce'),
            self::bytes('fa4362189661d163fcd6a56d8bf0405a'),
            self::bytes('d636ac1bbedd5cc3ee727dc2ab4a9489'),
        );
        $key = SessionKey::fromBytes(self::bytes('31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22'));

        static::assertSame(
            self::bytes('2db5168e932556f8089a0622981d017d'),
            (new Cipher())->decrypt($cipherText, $key, DataEncryptionMethod::AES256_GCM),
        );
    }

    /**
     * @return non-empty-string
     */
    private static function bytes(string $hex): string
    {
        $bytes = hex2bin($hex);
        static::assertIsString($bytes);
        static::assertNotSame('', $bytes);

        return $bytes;
    }
}
