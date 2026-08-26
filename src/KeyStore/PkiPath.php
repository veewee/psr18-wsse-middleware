<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\KeyStore;

use Soap\Psr18WsseMiddleware\KeyStore\Exception\InvalidCertificate;

/**
 * A PKIPath token body: the ASN.1 `SEQUENCE OF Certificate` the WS-Security X.509 Token Profile recommends
 * for carrying a certification path, in preference to a PKCS#7 wrapper.
 *
 * Only the outer SEQUENCE is unwrapped. Each element is handed back as its own certificate, in the order it
 * appeared, because interpreting that order is not this parser's business: the profile calls a PKIPath ordered
 * but states that PKCS#7 order carries no meaning, so the caller derives the end-entity from issuer linkage
 * instead of from position and is right either way.
 *
 * These bytes come from an unauthenticated peer, so every declared length is checked against what the input
 * actually holds rather than trusted. The number of certificates is deliberately not bounded: no specification
 * states a maximum, and a path that is merely long is refused later for having no single end-entity or for not
 * reaching a trust anchor.
 */
final class PkiPath
{
    private const SEQUENCE_TAG = 0x30;

    /**
     * @return non-empty-list<Certificate>
     *
     * @throws InvalidCertificate when the bytes are not a SEQUENCE, declare a length the input cannot hold, or
     *         hold no certificate
     */
    public static function certificates(string $der): array
    {
        $body = self::sequenceBody($der);

        $certificates = [];
        $offset = 0;
        $length = strlen($body);

        while ($offset < $length) {
            $certificates[] = Certificate::fromBase64Der(base64_encode(self::element($body, $offset)));
        }

        if ($certificates === []) {
            throw InvalidCertificate::malformedEncoding('the certificate path holds no certificate');
        }

        return $certificates;
    }

    /**
     * The token body carrying a whole certification path: the chain wrapped in one SEQUENCE.
     *
     * The chain is ordered leaf first, while ITU-T X.509 defines a PkiPath as ordered from the trust anchor
     * down to the end-entity, so the certificates go out in the opposite order to the one they are held in.
     * Reading stays order-agnostic on purpose (a peer may not honour this), but writing has to pick, and the
     * only defensible pick is what the format says.
     *
     * @throws InvalidCertificate when a certificate in the chain is not decodable PEM
     */
    public static function encode(CertificateChain $chain): string
    {
        $body = '';
        foreach (array_reverse($chain->all()) as $certificate) {
            $body .= (string) base64_decode($certificate->toBase64Der(), true);
        }

        return chr(self::SEQUENCE_TAG).self::encodeLength(strlen($body)).$body;
    }

    /**
     * A DER length in its shortest definite form: the short form below 128, otherwise the long form with a
     * leading count of the big-endian length bytes.
     */
    private static function encodeLength(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $bytes = '';
        for ($remaining = $length; $remaining > 0; $remaining >>= 8) {
            $bytes = chr($remaining & 0xFF).$bytes;
        }

        return chr(0x80 | strlen($bytes)).$bytes;
    }

    /**
     * The contents of the outer SEQUENCE, with its declared length confirmed to match the bytes present. A
     * length shorter than the input would leave trailing bytes nothing accounts for, so both directions are
     * rejected rather than silently tolerated.
     *
     * @throws InvalidCertificate
     */
    private static function sequenceBody(string $der): string
    {
        if ($der === '' || ord($der[0]) !== self::SEQUENCE_TAG) {
            throw InvalidCertificate::malformedEncoding('the certificate path is not an ASN.1 sequence');
        }

        $offset = 1;
        $length = self::length($der, $offset);

        if ($offset + $length !== strlen($der)) {
            throw InvalidCertificate::malformedEncoding('the certificate path length does not match its content');
        }

        return substr($der, $offset, $length);
    }

    /**
     * One complete TLV element starting at the offset, returned as raw DER and advancing the offset past it.
     *
     * @throws InvalidCertificate
     */
    private static function element(string $der, int &$offset): string
    {
        $start = $offset;

        // A certificate is itself a SEQUENCE, and it must be checked here rather than left to whoever parses
        // the bytes later: wrapping base64 into PEM does not parse anything, so without this the walker would
        // hand back a certificate-shaped object for any bytes at all. An empty one is refused for the same
        // reason: it cannot be a certificate, and a path of thousands of them costs a peer nothing to send.
        if (ord($der[$offset]) !== self::SEQUENCE_TAG) {
            throw InvalidCertificate::malformedEncoding('the certificate path holds something other than a certificate');
        }

        ++$offset;
        $length = self::length($der, $offset);

        if ($length === 0) {
            throw InvalidCertificate::malformedEncoding('the certificate path holds an empty certificate');
        }

        if ($offset + $length > strlen($der)) {
            throw InvalidCertificate::malformedEncoding('a certificate runs past the end of the path');
        }

        $offset += $length;

        return substr($der, $start, $offset - $start);
    }

    /**
     * Reads a DER length at the offset and advances it past the length bytes. Only the definite forms are
     * accepted: BER's indefinite form has no place in DER, and a length wider than the input could ever be is
     * refused rather than allocated for.
     *
     * @throws InvalidCertificate
     */
    private static function length(string $der, int &$offset): int
    {
        if ($offset >= strlen($der)) {
            throw InvalidCertificate::malformedEncoding('the certificate path ends inside a length');
        }

        $first = ord($der[$offset]);
        ++$offset;

        if ($first < 0x80) {
            return $first;
        }

        $count = $first & 0x7F;
        if ($count === 0 || $count > 4) {
            throw InvalidCertificate::malformedEncoding('the certificate path declares an unusable length');
        }

        $length = 0;
        for ($read = 0; $read < $count; ++$read) {
            if ($offset >= strlen($der)) {
                throw InvalidCertificate::malformedEncoding('the certificate path ends inside a length');
            }

            $length = ($length << 8) | ord($der[$offset]);
            ++$offset;
        }

        return $length;
    }
}
