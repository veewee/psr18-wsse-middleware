<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Default;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\KeyEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\KeyTransportAlgorithm;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy\DirectReferenceKeyIdentifier;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptedKeyBuilder;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptedPartId;
use VeeWee\Xml\Dom\Document;

final class EncryptedKeyBuilderTest extends TestCase
{
    private const XENC = 'http://www.w3.org/2001/04/xmlenc#';
    private const XENC11 = 'http://www.w3.org/2009/xmlenc11#';
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';
    private const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
    private const MGF1_SHA256 = 'http://www.w3.org/2009/xmlenc11#mgf1sha256';
    private const X509_TOKEN = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3';

    public function test_it_emits_the_encrypted_key_structure(): void
    {
        $document = Document::fromXmlString('<root/>');

        $encryptedKey = (new EncryptedKeyBuilder())->build(
            $document,
            'wrapped-key-bytes',
            new DirectReferenceKeyIdentifier('RecipientToken', self::X509_TOKEN),
            new Certificate('cert'),
            KeyTransportAlgorithm::legacyMgf1p(),
            [new EncryptedPartId('id-one'), new EncryptedPartId('id-two')],
        );

        static::assertSame('EncryptedKey', $encryptedKey->localName);

        $encryptionMethod = $this->child($encryptedKey, 'EncryptionMethod', self::XENC);
        static::assertSame(KeyEncryptionMethod::RSA_OAEP_MGF1P->value, $encryptionMethod->getAttribute('Algorithm'));
        // SHA-1 OAEP emits no DigestMethod / MGF children: the spec defaults already mean SHA-1 / MGF1-SHA1.
        static::assertSame(0, $encryptionMethod->getElementsByTagNameNS(self::DS, 'DigestMethod')->count());
        static::assertSame(0, $encryptionMethod->getElementsByTagNameNS(self::XENC11, 'MGF')->count());

        static::assertNotNull($this->child($encryptedKey, 'KeyInfo', self::DS));

        $cipherData = $this->child($encryptedKey, 'CipherData', self::XENC);
        $cipherValue = $this->child($cipherData, 'CipherValue', self::XENC);
        static::assertSame(base64_encode('wrapped-key-bytes'), $cipherValue->textContent);

        $referenceList = $this->child($encryptedKey, 'ReferenceList', self::XENC);
        $references = $referenceList->getElementsByTagNameNS(self::XENC, 'DataReference');
        static::assertSame(2, $references->count());
        static::assertSame('#id-one', $references->item(0)?->getAttribute('URI'));
        static::assertSame('#id-two', $references->item(1)?->getAttribute('URI'));
    }

    public function test_it_emits_digest_and_mgf_children_for_sha256(): void
    {
        $document = Document::fromXmlString('<root/>');

        $encryptedKey = (new EncryptedKeyBuilder())->build(
            $document,
            'wrapped-key-bytes',
            new DirectReferenceKeyIdentifier('RecipientToken', self::X509_TOKEN),
            new Certificate('cert'),
            KeyTransportAlgorithm::oaepSha256(),
            [new EncryptedPartId('id-one')],
        );

        $encryptionMethod = $this->child($encryptedKey, 'EncryptionMethod', self::XENC);
        static::assertSame(KeyEncryptionMethod::RSA_OAEP->value, $encryptionMethod->getAttribute('Algorithm'));

        $digest = $encryptionMethod->getElementsByTagNameNS(self::DS, 'DigestMethod');
        static::assertSame(1, $digest->count());
        static::assertSame(self::SHA256, $digest->item(0)?->getAttribute('Algorithm'));

        $mgf = $encryptionMethod->getElementsByTagNameNS(self::XENC11, 'MGF');
        static::assertSame(1, $mgf->count());
        static::assertSame(self::MGF1_SHA256, $mgf->item(0)?->getAttribute('Algorithm'));
    }

    private function child(Element $parent, string $localName, string $namespace): Element
    {
        foreach ($parent->childNodes as $child) {
            if ($child instanceof Element && $child->localName === $localName && $child->namespaceURI === $namespace) {
                return $child;
            }
        }

        static::fail(sprintf('Missing child %s', $localName));
    }
}
