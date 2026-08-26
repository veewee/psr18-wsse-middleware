<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\OpenSSL;

use LogicException;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\OpenSSL\Mac;

final class MacTest extends TestCase
{
    /**
     * RFC 4231 test case 2: the key "Jefe" over "what do ya want for nothing?". A published vector rather than
     * a round-trip against ourselves, so a wrong key derivation or a hex/raw mix-up cannot pass.
     */
    public function test_it_matches_the_published_hmac_vectors(): void
    {
        $mac = new Mac();
        $key = SessionKey::fromBytes('Jefe');
        $data = 'what do ya want for nothing?';

        static::assertSame(
            '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
            bin2hex($mac->compute($data, $key, SignatureMethod::HMAC_SHA256)),
        );
        static::assertSame(
            'af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e'
            .'8e2240ca5e69e2c78b3239ecfab21649',
            bin2hex($mac->compute($data, $key, SignatureMethod::HMAC_SHA384)),
        );
        static::assertSame(
            '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554'
            .'9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737',
            bin2hex($mac->compute($data, $key, SignatureMethod::HMAC_SHA512)),
        );
    }

    public function test_it_computes_a_mac_of_the_digest_length_for_every_hmac_method(): void
    {
        $mac = new Mac();
        $key = SessionKey::fromBytes(str_repeat("\x0b", 32));

        foreach ([
            SignatureMethod::HMAC_SHA1,
            SignatureMethod::HMAC_SHA224,
            SignatureMethod::HMAC_SHA256,
            SignatureMethod::HMAC_SHA384,
            SignatureMethod::HMAC_SHA512,
        ] as $method) {
            static::assertSame(
                $method->hmacKeyLength(),
                strlen($mac->compute('payload', $key, $method)),
                $method->name,
            );
        }
    }

    public function test_a_mac_verifies_against_the_key_that_produced_it_and_nothing_else(): void
    {
        $mac = new Mac();
        $key = SessionKey::fromBytes(str_repeat("\x2a", 32));
        $other = SessionKey::fromBytes(str_repeat("\x2b", 32));
        $value = $mac->compute('payload', $key, SignatureMethod::HMAC_SHA256);

        static::assertTrue($mac->verify('payload', $key, $value, SignatureMethod::HMAC_SHA256));
        static::assertFalse($mac->verify('tampered', $key, $value, SignatureMethod::HMAC_SHA256));
        static::assertFalse($mac->verify('payload', $other, $value, SignatureMethod::HMAC_SHA256));
        static::assertFalse($mac->verify('payload', $key, $value, SignatureMethod::HMAC_SHA512));
    }

    /**
     * A truncated MAC must not verify. Accepting a prefix is what makes ds:HMACOutputLength a forgery lever,
     * and the constant-time comparison this uses refuses unequal lengths outright.
     */
    public function test_a_truncated_mac_does_not_verify(): void
    {
        $mac = new Mac();
        $key = SessionKey::fromBytes(str_repeat("\x2a", 32));
        $value = $mac->compute('payload', $key, SignatureMethod::HMAC_SHA256);

        static::assertFalse($mac->verify('payload', $key, substr($value, 0, 1), SignatureMethod::HMAC_SHA256));
        static::assertFalse($mac->verify('payload', $key, substr($value, 0, 31), SignatureMethod::HMAC_SHA256));
    }

    public function test_an_empty_key_is_refused_rather_than_keyed_with_nothing(): void
    {
        $this->expectException(LogicException::class);

        (new Mac())->compute('payload', SessionKey::fromBytes(''), SignatureMethod::HMAC_SHA256);
    }

    public function test_a_non_hmac_method_cannot_be_computed_as_a_mac(): void
    {
        $this->expectException(LogicException::class);

        (new Mac())->compute(
            'payload',
            SessionKey::fromBytes(str_repeat("\x2a", 32)),
            SignatureMethod::RSA_SHA256,
        );
    }
}
