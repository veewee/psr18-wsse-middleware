<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\KeyStore\Fixture;

use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use RuntimeException;

/**
 * Generates a self-signed CA and a leaf certificate signed by it, then packs the leaf, its key and
 * (optionally) the CA chain into a PKCS#12 blob for the loader tests.
 */
final class Pkcs12Fixture
{
    private function __construct(public readonly string $p12)
    {
    }

    public static function create(string $passphrase, bool $withCaChain = true): self
    {
        $caKey = self::newKey();
        $caCert = self::selfSign($caKey, '/CN=Test CA');

        $leafKey = self::newKey();
        $leafCert = self::signWith($leafKey, $caCert, $caKey, '/CN=Test Leaf');

        $options = [];
        if ($withCaChain) {
            $caPem = '';
            if (!openssl_x509_export($caCert, $caPem)) {
                throw new RuntimeException('Unable to export the CA certificate.');
            }
            $options['extracerts'] = [$caPem];
        }

        $p12 = '';
        if (!openssl_pkcs12_export($leafCert, $p12, $leafKey, $passphrase, $options)) {
            throw new RuntimeException('Unable to export the PKCS#12 fixture.');
        }

        return new self($p12);
    }

    public function writeToTempFile(): string
    {
        $file = tempnam(sys_get_temp_dir(), 'wsse-p12-');
        if ($file === false || file_put_contents($file, $this->p12) === false) {
            throw new RuntimeException('Unable to write the PKCS#12 fixture file.');
        }

        return $file;
    }

    private static function newKey(): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048,
        ]);
        if ($key === false) {
            throw new RuntimeException('Unable to generate a private key.');
        }

        return $key;
    }

    private static function selfSign(OpenSSLAsymmetricKey $key, string $dn): OpenSSLCertificate
    {
        $csr = openssl_csr_new(self::distinguishedName($dn), $key, ['digest_alg' => 'sha256']);
        if ($csr === false) {
            throw new RuntimeException('Unable to create a certificate signing request.');
        }

        $cert = openssl_csr_sign($csr, null, $key, 3650, ['digest_alg' => 'sha256']);
        if ($cert === false) {
            throw new RuntimeException('Unable to self-sign the certificate.');
        }

        return $cert;
    }

    private static function signWith(
        OpenSSLAsymmetricKey $key,
        OpenSSLCertificate $caCert,
        OpenSSLAsymmetricKey $caKey,
        string $dn,
    ): OpenSSLCertificate {
        $csr = openssl_csr_new(self::distinguishedName($dn), $key, ['digest_alg' => 'sha256']);
        if ($csr === false) {
            throw new RuntimeException('Unable to create a certificate signing request.');
        }

        $cert = openssl_csr_sign($csr, $caCert, $caKey, 3650, ['digest_alg' => 'sha256']);
        if ($cert === false) {
            throw new RuntimeException('Unable to sign the leaf certificate.');
        }

        return $cert;
    }

    /**
     * @return array<string, string>
     */
    private static function distinguishedName(string $dn): array
    {
        $name = [];
        foreach (explode('/', trim($dn, '/')) as $part) {
            [$field, $value] = explode('=', $part, 2);
            $name[$field] = $value;
        }

        return $name;
    }
}
