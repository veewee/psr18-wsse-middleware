<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Default;

use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\KeyTransportAlgorithm;
use Soap\Psr18WsseMiddleware\Algorithm\OaepHash;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\OpenSSL\KeyTransport;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptedKeyReader;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\DecryptionFailed;
use VeeWee\Xml\Dom\Document;

final class EncryptedKeyReaderTest extends TestCase
{
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const XENC = 'http://www.w3.org/2001/04/xmlenc#';
    private const XENC11 = 'http://www.w3.org/2009/xmlenc11#';
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';
    private const RSA_OAEP = 'http://www.w3.org/2009/xmlenc11#rsa-oaep';
    private const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
    private const SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
    private const MGF1_SHA1 = 'http://www.w3.org/2009/xmlenc11#mgf1sha1';
    private const MGF1_SHA256 = 'http://www.w3.org/2009/xmlenc11#mgf1sha256';

    public function test_it_reads_a_sha256_encrypted_key(): void
    {
        [$key, $certificate] = $this->keyAndCertificate();
        $sessionKey = SessionKey::fromBytes(random_bytes(32));
        $wrapped = (new KeyTransport())->wrap($sessionKey, $certificate, KeyTransportAlgorithm::oaepSha256());

        $document = $this->envelope($wrapped, [
            ['DigestMethod', self::DS, self::SHA256],
            ['MGF', self::XENC11, self::MGF1_SHA256],
        ]);

        $sessionKeyRead = (new EncryptedKeyReader(new KeyTransport()))->read($document, $key);

        static::assertSame($sessionKey->bytes(), $sessionKeyRead->bytes());
    }

    public function test_a_disallowed_digest_collapses_to_a_uniform_failure(): void
    {
        [$key, $certificate] = $this->keyAndCertificate();
        $wrapped = (new KeyTransport())->wrap(SessionKey::fromBytes(random_bytes(32)), $certificate, KeyTransportAlgorithm::oaepSha256());

        // SHA-384 has no OAEP-hash counterpart, so it is rejected before any unwrap.
        $document = $this->envelope($wrapped, [
            ['DigestMethod', self::DS, self::SHA384],
            ['MGF', self::XENC11, self::MGF1_SHA256],
        ]);

        static::assertSame($this->uniformMessage(), $this->captureFailure($document, $key));
    }

    public function test_a_profile_excluding_sha256_collapses_to_a_uniform_failure(): void
    {
        [$key, $certificate] = $this->keyAndCertificate();
        $wrapped = (new KeyTransport())->wrap(SessionKey::fromBytes(random_bytes(32)), $certificate, KeyTransportAlgorithm::oaepSha256());

        $document = $this->envelope($wrapped, [
            ['DigestMethod', self::DS, self::SHA256],
            ['MGF', self::XENC11, self::MGF1_SHA256],
        ]);

        $profile = new SecurityProfile(acceptedOaepHashes: [OaepHash::Sha1]);

        $message = $this->captureFailure($document, $key, $profile);
        static::assertSame($this->uniformMessage(), $message);
    }

    public function test_a_digest_mgf_mismatch_collapses_to_a_uniform_failure(): void
    {
        [$key, $certificate] = $this->keyAndCertificate();
        $wrapped = (new KeyTransport())->wrap(SessionKey::fromBytes(random_bytes(32)), $certificate, KeyTransportAlgorithm::oaepSha256());

        // A SHA-256 digest paired with an MGF1-SHA1 child is an inconsistent pair and is rejected.
        $document = $this->envelope($wrapped, [
            ['DigestMethod', self::DS, self::SHA256],
            ['MGF', self::XENC11, self::MGF1_SHA1],
        ]);

        static::assertSame($this->uniformMessage(), $this->captureFailure($document, $key));
    }

    public function test_a_non_empty_oaep_params_collapses_to_a_uniform_failure(): void
    {
        [$key, $certificate] = $this->keyAndCertificate();
        $wrapped = (new KeyTransport())->wrap(SessionKey::fromBytes(random_bytes(32)), $certificate, KeyTransportAlgorithm::oaepSha256());

        $document = $this->envelope($wrapped, [
            ['DigestMethod', self::DS, self::SHA256],
            ['MGF', self::XENC11, self::MGF1_SHA256],
            ['OAEPparams', self::XENC, null, base64_encode('label')],
        ]);

        static::assertSame($this->uniformMessage(), $this->captureFailure($document, $key));
    }

    private function uniformMessage(): string
    {
        return DecryptionFailed::withReason('Unable to unwrap the session key.')->getMessage();
    }

    private function captureFailure(Document $document, Key $key, ?SecurityProfile $profile = null): string
    {
        try {
            (new EncryptedKeyReader(new KeyTransport()))->read($document, $key, $profile);
        } catch (DecryptionFailed $exception) {
            return $exception->getMessage();
        }

        static::fail('Expected a DecryptionFailed exception.');
    }

    /**
     * @param list<array{0: string, 1: string, 2: string|null, 3?: string}> $methodChildren
     */
    private function envelope(string $wrapped, array $methodChildren): Document
    {
        $children = '';
        foreach ($methodChildren as $child) {
            [$localName, $namespace, $algorithm] = $child;
            $text = $child[3] ?? '';
            $prefix = $namespace === self::DS ? 'ds' : ($namespace === self::XENC11 ? 'xenc11' : 'xenc');
            $attr = $algorithm === null ? '' : ' Algorithm="'.$algorithm.'"';
            $children .= '<'.$prefix.':'.$localName.$attr.'>'.$text.'</'.$prefix.':'.$localName.'>';
        }

        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"'
            .' xmlns:wsse="'.self::WSSE.'" xmlns:xenc="'.self::XENC.'"'
            .' xmlns:xenc11="'.self::XENC11.'" xmlns:ds="'.self::DS.'">'
            .'<soap:Header><wsse:Security>'
            .'<xenc:EncryptedKey>'
            .'<xenc:EncryptionMethod Algorithm="'.self::RSA_OAEP.'">'.$children.'</xenc:EncryptionMethod>'
            .'<xenc:CipherData><xenc:CipherValue>'.base64_encode($wrapped).'</xenc:CipherValue></xenc:CipherData>'
            .'<xenc:ReferenceList><xenc:DataReference URI="#part"/></xenc:ReferenceList>'
            .'</xenc:EncryptedKey>'
            .'</wsse:Security></soap:Header><soap:Body/></soap:Envelope>'
        );
    }

    /**
     * @return array{0: Key, 1: Certificate}
     */
    private function keyAndCertificate(): array
    {
        $private = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        static::assertInstanceOf(OpenSSLAsymmetricKey::class, $private);

        static::assertTrue(openssl_pkey_export($private, $privatePem));
        static::assertIsString($privatePem);

        $csr = openssl_csr_new(['commonName' => 'wsse-reader-test'], $private);
        static::assertNotFalse($csr);

        $certificate = openssl_csr_sign($csr, null, $private, 365);
        static::assertNotFalse($certificate);

        static::assertTrue(openssl_x509_export($certificate, $certificatePem));
        static::assertIsString($certificatePem);

        return [new Key($privatePem), new Certificate($certificatePem)];
    }
}
