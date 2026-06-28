<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyStore;

use ParagonIE\HiddenString\HiddenString;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use function Psl\File\read;

/**
 * Contains a PEM representation of a public X.509 Certificate.
 */
final class Certificate implements KeyInterface
{
    private HiddenString $key;

    public function __construct(string $key)
    {
        $this->key = new HiddenString($key);
    }

    /**
     * @param non-empty-string $file
     */
    public static function fromFile(string $file): self
    {
        return new self(read($file));
    }

    /**
     * Wraps base64-encoded DER bytes back into a PEM certificate. Whitespace in the input is normalised
     * away first so the result round-trips with toBase64Der().
     */
    public static function fromBase64Der(string $base64Der): self
    {
        $normalised = (string) preg_replace('/\s/', '', $base64Der);

        $pem = "-----BEGIN CERTIFICATE-----\n"
            .chunk_split($normalised, 64, "\n")
            .'-----END CERTIFICATE-----'."\n";

        return new self($pem);
    }

    /**
     * The base64-encoded DER body of the certificate: the PEM with its armor lines and all whitespace
     * removed. This is the wire form a wsse:BinarySecurityToken carries.
     *
     * @throws WsseHeaderException when the certificate is not decodable PEM
     */
    public function toBase64Der(): string
    {
        $stripped = preg_replace('/-----[^-]+-----|\s/', '', $this->contents());
        $der = base64_decode((string) $stripped, true);

        if ($der === false || $der === '') {
            throw WsseHeaderException::bstEncodingFailed('the certificate is not valid base64-encoded PEM');
        }

        return base64_encode($der);
    }

    public function contents(): string
    {
        return $this->key->getString();
    }
}
