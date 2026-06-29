<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\KeyStore\Metadata;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Metadata\SubjectKeyIdentifier;

final class SubjectKeyIdentifierTest extends TestCase
{
    public function test_it_renders_colon_separated_hex_as_base64_bytes(): void
    {
        static::assertSame(
            base64_encode("\x12\xAB\xCD"),
            SubjectKeyIdentifier::fromHex('12:AB:CD')->toBase64(),
        );
    }

    public function test_it_strips_a_leading_keyid_marker(): void
    {
        static::assertSame(
            base64_encode("\x12\xAB\xCD"),
            SubjectKeyIdentifier::fromHex('keyid:12:AB:CD')->toBase64(),
        );
    }

    public function test_it_throws_on_malformed_hex(): void
    {
        $this->expectException(CryptoOperationFailed::class);
        SubjectKeyIdentifier::fromHex('not-hex');
    }

    public function test_it_throws_on_empty_hex(): void
    {
        $this->expectException(CryptoOperationFailed::class);
        SubjectKeyIdentifier::fromHex('');
    }

    public function test_it_round_trips_through_base64(): void
    {
        $base64 = base64_encode("\x12\xAB\xCD");

        static::assertSame($base64, SubjectKeyIdentifier::fromBase64($base64)->toBase64());
    }

    public function test_it_throws_on_invalid_base64(): void
    {
        $this->expectException(CryptoOperationFailed::class);
        SubjectKeyIdentifier::fromBase64('!!!not base64!!!');
    }

    public function test_it_equals_the_same_identifier_built_either_way(): void
    {
        $fromHex = SubjectKeyIdentifier::fromHex('12:AB:CD');
        $fromBase64 = SubjectKeyIdentifier::fromBase64(base64_encode("\x12\xAB\xCD"));

        static::assertTrue($fromHex->equals($fromBase64));
    }

    public function test_it_does_not_equal_a_different_identifier(): void
    {
        static::assertFalse(
            SubjectKeyIdentifier::fromHex('12:AB:CD')->equals(SubjectKeyIdentifier::fromHex('12:AB:CE')),
        );
    }
}
