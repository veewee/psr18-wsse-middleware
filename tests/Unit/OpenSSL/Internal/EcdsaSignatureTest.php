<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\OpenSSL\Internal;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\OpenSSL\Internal\EcdsaSignature;

final class EcdsaSignatureTest extends TestCase
{
    /**
     * A DER signature emitted by openssl_sign converts to a fixed-width P1363 pair and back to the same DER.
     */
    public function test_it_round_trips_a_real_signature_for_each_curve(): void
    {
        foreach (['prime256v1' => 32, 'secp384r1' => 48, 'secp521r1' => 66] as $curve => $coordinateBytes) {
            $der = $this->realDerSignature($curve);

            $p1363 = EcdsaSignature::derToP1363($der, $coordinateBytes);
            static::assertSame($coordinateBytes * 2, strlen($p1363), $curve);

            static::assertSame(bin2hex($der), bin2hex(EcdsaSignature::p1363ToDer($p1363)), $curve);
        }
    }

    /**
     * A high-bit-set integer is stored in DER with a leading 0x00 sign byte; converting to P1363 strips it and
     * left-pads to the coordinate width, and the reverse re-adds it.
     */
    public function test_it_handles_a_high_bit_set_integer(): void
    {
        // r has its top bit set (0xFF...), s is small. DER therefore prefixes r with 0x00.
        $r = str_repeat("\xff", 32);
        $s = str_pad("\x01", 32, "\x00", STR_PAD_LEFT);
        $p1363 = $r.$s;

        $der = EcdsaSignature::p1363ToDer($p1363);
        // INTEGER r is 33 bytes (0x00 sign byte + 32), so it is tagged 0x02, length 0x21, then 0x00 0xff...
        static::assertSame('30', bin2hex(substr($der, 0, 1)));
        static::assertStringContainsString('022100ff', bin2hex($der));

        static::assertSame(bin2hex($p1363), bin2hex(EcdsaSignature::derToP1363($der, 32)));
    }

    /**
     * Leading zero coordinate bytes survive the round trip: DER drops them to a minimal integer, P1363 pads
     * them back to the fixed width.
     */
    public function test_it_handles_leading_zero_coordinate_bytes(): void
    {
        $r = str_pad("\x05", 32, "\x00", STR_PAD_LEFT);
        $s = str_pad("\x06", 32, "\x00", STR_PAD_LEFT);
        $p1363 = $r.$s;

        $der = EcdsaSignature::p1363ToDer($p1363);
        // Each integer minimised to a single significant byte.
        static::assertSame('3006020105020106', bin2hex($der));

        static::assertSame(bin2hex($p1363), bin2hex(EcdsaSignature::derToP1363($der, 32)));
    }

    /**
     * The 66-byte P-521 coordinate width is odd; the converter must respect the supplied width rather than
     * assume an even byte count per coordinate.
     */
    public function test_it_supports_the_odd_p521_coordinate_width(): void
    {
        $der = $this->realDerSignature('secp521r1');

        $p1363 = EcdsaSignature::derToP1363($der, 66);
        static::assertSame(132, strlen($p1363));
        static::assertSame(bin2hex($der), bin2hex(EcdsaSignature::p1363ToDer($p1363)));
    }

    /**
     * @param callable(): string $convert
     */
    #[DataProvider('malformedInputs')]
    public function test_it_rejects_malformed_input(callable $convert): void
    {
        $this->expectException(InvalidArgumentException::class);
        $convert();
    }

    /**
     * @return iterable<string, array{0: callable(): string}>
     */
    public static function malformedInputs(): iterable
    {
        yield 'p1363 of odd length' => [static fn (): string => EcdsaSignature::p1363ToDer(str_repeat("\x01", 63))];
        yield 'der that is not a sequence' => [static fn (): string => EcdsaSignature::derToP1363("\x02\x01\x01", 32)];
        // SEQUENCE wrapping a non-INTEGER (0x04) element.
        yield 'der inner element not an integer' => [static fn (): string => EcdsaSignature::derToP1363("\x30\x03\x04\x01\x01", 32)];
        // A well-formed two-integer SEQUENCE with one surplus byte appended after it.
        yield 'trailing bytes after the sequence' => [static fn (): string => EcdsaSignature::derToP1363("\x30\x06\x02\x01\x01\x02\x01\x01\x00", 32)];
        // SEQUENCE wrapping three INTEGERs: r, s and an unexpected third element.
        yield 'sequence carrying more than two integers' => [static fn (): string => EcdsaSignature::derToP1363("\x30\x09\x02\x01\x01\x02\x01\x01\x02\x01\x01", 32)];
        // An integer body of 33 significant bytes cannot fit a 32-byte coordinate.
        yield 'coordinate wider than the curve' => [static function (): string {
            $oversized = str_repeat("\x01", 33);

            return EcdsaSignature::derToP1363("\x30".chr(2 + strlen($oversized) + 3)."\x02".chr(strlen($oversized)).$oversized."\x02\x01\x01", 32);
        }];
    }

    private function realDerSignature(string $curve): string
    {
        $key = openssl_pkey_new(['curve_name' => $curve, 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        static::assertNotFalse($key);

        static::assertTrue(openssl_sign('payload', $der, $key, OPENSSL_ALGO_SHA256));
        static::assertIsString($der);

        return $der;
    }
}
