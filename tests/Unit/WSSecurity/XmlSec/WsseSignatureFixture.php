<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\XmlSec;

use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use RuntimeException;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\OpenSSL\Signer as OpenSslSigner;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy\DirectReferenceKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Key;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\KeyHandle;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\Wsse\WsuIdMinter;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Canonicalization\DomCanonicalizer;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\PartLocator;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Signing\DigestCalculator;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Signing\KeyInfoBuilder;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Signing\ReferenceCollector;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Signing\SignedInfoBuilder;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Signing\Signer;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Signing\SigningRequest;
use VeeWee\Xml\Dom\Document;

/**
 * Builds signed WSSE envelopes for the verifier tests. It mints a CA and a leaf key pair in process so a
 * signed document can also be trust-anchored to that CA, then drives the real B3 signer to produce the
 * ds:Signature the B4 verifier reads back.
 */
final class WsseSignatureFixture
{
    public const SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    public const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    public const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
    public const DS = 'http://www.w3.org/2000/09/xmldsig#';
    public const X509_TOKEN
        = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3';
    public const BST_ID = 'SignedToken';

    private function __construct(
        public readonly Key $leafKey,
        public readonly Certificate $leafCertificate,
        public readonly Certificate $caCertificate,
    ) {
    }

    /**
     * A leaf key and certificate signed by a generated CA. The CA certificate is the trust anchor.
     */
    public static function caSignedLeaf(): self
    {
        [$caKey, $caCert] = self::caKeyPair();

        $leafPrivate = self::rsaKey();
        $leafCsr = openssl_csr_new(['commonName' => 'WSSE Round Trip Leaf'], $leafPrivate);
        if ($leafCsr === false) {
            throw new RuntimeException('Unable to create the leaf CSR.');
        }

        $leafCert = openssl_csr_sign(
            $leafCsr,
            $caCert,
            $caKey,
            365,
            ['digest_alg' => 'sha256'],
        );
        if ($leafCert === false) {
            throw new RuntimeException('Unable to sign the leaf certificate.');
        }

        return new self(
            new Key(self::exportKey($leafPrivate)),
            new Certificate(self::exportCertificate($leafCert)),
            new Certificate(self::exportCertificate($caCert)),
        );
    }

    /**
     * A self-signed leaf key and certificate with no CA. Used for untrusted-signer cases.
     */
    public static function selfSignedLeaf(): self
    {
        $private = self::rsaKey();
        $csr = openssl_csr_new(['commonName' => 'WSSE Self Signed'], $private);
        if ($csr === false) {
            throw new RuntimeException('Unable to create the self-signed CSR.');
        }

        $cert = openssl_csr_sign($csr, null, $private, 365, ['digest_alg' => 'sha256']);
        if ($cert === false) {
            throw new RuntimeException('Unable to create the self-signed certificate.');
        }

        $certificate = new Certificate(self::exportCertificate($cert));

        return new self(new Key(self::exportKey($private)), $certificate, $certificate);
    }

    /**
     * Signs the given parts into a fresh envelope carrying a BinarySecurityToken the signature references.
     *
     * @param non-empty-list<Part> $parts
     */
    public function sign(
        array $parts,
        bool $withTimestamp = false,
        SignatureMethod $signatureMethod = SignatureMethod::RSA_SHA256,
        DigestMethod $digestMethod = DigestMethod::SHA256,
    ): Document {
        $document = $this->envelope($withTimestamp);

        $this->signer()->sign($document, new SigningRequest(
            parts: $parts,
            signingKey: KeyHandle::for($this->leafKey),
            signingCertificate: $this->leafCertificate,
            keyIdentifier: new DirectReferenceKeyIdentifier(self::BST_ID, self::X509_TOKEN),
            signatureMethod: $signatureMethod,
            digestMethod: $digestMethod,
            canonicalization: SignatureCanonicalization::EXC_C14N,
        ));

        return $document;
    }

    public function envelope(bool $withTimestamp = false): Document
    {
        $timestamp = $withTimestamp
            ? '<wsu:Timestamp wsu:Id="TS"><wsu:Created>2026-01-01T00:00:00Z</wsu:Created></wsu:Timestamp>'
            : '';

        return Document::fromXmlString(
            '<soap:Envelope'
            .' xmlns:soap="'.self::SOAP.'"'
            .' xmlns:wsse="'.self::WSSE.'"'
            .' xmlns:wsu="'.self::WSU.'"'
            .' xmlns:ds="'.self::DS.'">'
            .'<soap:Header><wsse:Security>'
            .$this->binarySecurityToken()
            .$timestamp
            .'</wsse:Security></soap:Header>'
            .'<soap:Body><data>x</data></soap:Body>'
            .'</soap:Envelope>'
        );
    }

    public function binarySecurityToken(): string
    {
        return '<wsse:BinarySecurityToken'
            .' wsu:Id="'.self::BST_ID.'"'
            .' ValueType="'.self::X509_TOKEN.'"'
            .' EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">'
            .$this->certificateBase64Der($this->leafCertificate)
            .'</wsse:BinarySecurityToken>';
    }

    public function certificateBase64Der(Certificate $certificate): string
    {
        $pem = $certificate->contents();
        $body = preg_replace('/-----(BEGIN|END) CERTIFICATE-----|\s+/', '', $pem);
        if (!is_string($body) || $body === '') {
            throw new RuntimeException('Unable to read the certificate body.');
        }

        return $body;
    }

    public function signer(): Signer
    {
        $canonicalizer = new DomCanonicalizer();

        return new Signer(
            new ReferenceCollector(new WsuIdMinter(), new PartLocator()),
            new DigestCalculator($canonicalizer, new Digest()),
            new SignedInfoBuilder(),
            new KeyInfoBuilder(),
            $canonicalizer,
            new OpenSslSigner(),
        );
    }

    private static function rsaKey(): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        if ($key === false) {
            throw new RuntimeException('Unable to generate an RSA key.');
        }

        return $key;
    }

    /**
     * @return array{0: OpenSSLAsymmetricKey, 1: OpenSSLCertificate}
     */
    private static function caKeyPair(): array
    {
        $caKey = self::rsaKey();
        $caCsr = openssl_csr_new(['commonName' => 'WSSE Round Trip CA'], $caKey);
        if ($caCsr === false) {
            throw new RuntimeException('Unable to create the CA CSR.');
        }

        $caCert = openssl_csr_sign(
            $caCsr,
            null,
            $caKey,
            3650,
            ['digest_alg' => 'sha256', 'x509_extensions' => 'v3_ca'],
        );
        if ($caCert === false) {
            throw new RuntimeException('Unable to create the CA certificate.');
        }

        return [$caKey, $caCert];
    }

    private static function exportKey(OpenSSLAsymmetricKey $key): string
    {
        if (!openssl_pkey_export($key, $pem)) {
            throw new RuntimeException('Unable to export the private key.');
        }

        return (string) $pem;
    }

    private static function exportCertificate(OpenSSLCertificate $certificate): string
    {
        if (!openssl_x509_export($certificate, $pem)) {
            throw new RuntimeException('Unable to export the certificate.');
        }

        return (string) $pem;
    }
}
