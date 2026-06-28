<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL\Internal;

use InvalidArgumentException;

/**
 * Converts ECDSA signatures between the two encodings the engine straddles. OpenSSL signs and verifies in DER
 * (a SEQUENCE of two INTEGERs r and s), while XML Signature carries the value as a fixed-width pair r||s with
 * each coordinate left-padded to the curve size. Signing goes DER to fixed-width; verifying goes the other
 * way before the value reaches OpenSSL.
 *
 * @internal
 */
final class EcdsaSignature
{
    /**
     * @param int $coordinateBytes the curve coordinate width derived from the key, used to left-pad r and s
     *
     * @throws InvalidArgumentException when the DER is malformed or a coordinate exceeds the curve width
     */
    public static function derToP1363(string $der, int $coordinateBytes): string
    {
        $offset = 0;
        $length = strlen($der);

        self::expectTag($der, $offset, 0x30);
        $sequenceLength = self::readLength($der, $offset);
        if ($offset + $sequenceLength !== $length) {
            throw new InvalidArgumentException('The DER signature has trailing or truncated content.');
        }

        $r = self::readInteger($der, $offset);
        $s = self::readInteger($der, $offset);
        if ($offset !== $length) {
            throw new InvalidArgumentException('The DER signature carries more than two integers.');
        }

        return self::pad($r, $coordinateBytes).self::pad($s, $coordinateBytes);
    }

    /**
     * @throws InvalidArgumentException when the value is not an even-length r||s pair
     */
    public static function p1363ToDer(string $p1363): string
    {
        $length = strlen($p1363);
        if ($length === 0 || $length % 2 !== 0) {
            throw new InvalidArgumentException('The P1363 signature must be a non-empty even-length r||s pair.');
        }

        $half = intdiv($length, 2);
        $r = self::encodeInteger(substr($p1363, 0, $half));
        $s = self::encodeInteger(substr($p1363, $half));

        $body = $r.$s;

        return "\x30".self::encodeLength(strlen($body)).$body;
    }

    private static function expectTag(string $der, int &$offset, int $tag): void
    {
        if ($offset >= strlen($der) || ord($der[$offset]) !== $tag) {
            throw new InvalidArgumentException('The DER signature has an unexpected tag.');
        }

        ++$offset;
    }

    /**
     * Reads a DER length, supporting the long form where the first byte's high bit flags how many length bytes
     * follow.
     */
    private static function readLength(string $der, int &$offset): int
    {
        if ($offset >= strlen($der)) {
            throw new InvalidArgumentException('The DER signature is truncated at a length field.');
        }

        $first = ord($der[$offset]);
        ++$offset;

        if ($first < 0x80) {
            return $first;
        }

        $byteCount = $first & 0x7f;
        if ($byteCount === 0 || $byteCount > 4 || $offset + $byteCount > strlen($der)) {
            throw new InvalidArgumentException('The DER signature has an invalid length encoding.');
        }

        $value = 0;
        for ($i = 0; $i < $byteCount; ++$i) {
            $value = ($value << 8) | ord($der[$offset]);
            ++$offset;
        }

        return $value;
    }

    /**
     * Reads one INTEGER body and returns the raw magnitude: the leading 0x00 sign byte is dropped, and any
     * surplus leading zero bytes are trimmed so the value is a minimal big-endian magnitude.
     */
    private static function readInteger(string $der, int &$offset): string
    {
        self::expectTag($der, $offset, 0x02);
        $length = self::readLength($der, $offset);
        if ($length === 0 || $offset + $length > strlen($der)) {
            throw new InvalidArgumentException('The DER signature has a malformed integer.');
        }

        $value = substr($der, $offset, $length);
        $offset += $length;

        if ($value[0] === "\x00" && strlen($value) > 1) {
            $value = substr($value, 1);
        }

        return ltrim($value, "\x00");
    }

    /**
     * Left-pads the raw magnitude to the fixed coordinate width, rejecting a value that does not fit.
     */
    private static function pad(string $value, int $coordinateBytes): string
    {
        if (strlen($value) > $coordinateBytes) {
            throw new InvalidArgumentException('An ECDSA coordinate is wider than the curve allows.');
        }

        return str_pad($value, $coordinateBytes, "\x00", STR_PAD_LEFT);
    }

    /**
     * Encodes a fixed-width coordinate as a minimal DER INTEGER: surplus leading zeros are dropped and a 0x00
     * sign byte is prepended when the high bit would otherwise read as negative.
     */
    private static function encodeInteger(string $coordinate): string
    {
        $value = ltrim($coordinate, "\x00");
        if ($value === '') {
            $value = "\x00";
        }

        if ((ord($value[0]) & 0x80) !== 0) {
            $value = "\x00".$value;
        }

        return "\x02".self::encodeLength(strlen($value)).$value;
    }

    private static function encodeLength(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $bytes = '';
        while ($length > 0) {
            $bytes = chr($length & 0xff).$bytes;
            $length >>= 8;
        }

        return chr(0x80 | strlen($bytes)).$bytes;
    }
}
