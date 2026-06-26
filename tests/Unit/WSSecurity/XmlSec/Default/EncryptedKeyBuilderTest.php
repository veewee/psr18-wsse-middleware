<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\XmlSec\Default;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\KeyEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy\DirectReferenceKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Default\EncryptedKeyBuilder;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Default\EncryptedPartId;
use VeeWee\Xml\Dom\Document;

final class EncryptedKeyBuilderTest extends TestCase
{
    private const XENC = 'http://www.w3.org/2001/04/xmlenc#';
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';
    private const X509_TOKEN = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3';

    public function test_it_emits_the_encrypted_key_structure(): void
    {
        $document = Document::fromXmlString('<root/>');

        $encryptedKey = (new EncryptedKeyBuilder())->build(
            $document,
            'wrapped-key-bytes',
            new DirectReferenceKeyIdentifier('RecipientToken', self::X509_TOKEN),
            new Certificate('cert'),
            KeyEncryptionMethod::RSA_OAEP_MGF1P,
            [new EncryptedPartId('id-one'), new EncryptedPartId('id-two')],
        );

        static::assertSame('EncryptedKey', $encryptedKey->localName);

        $encryptionMethod = $this->child($encryptedKey, 'EncryptionMethod', self::XENC);
        static::assertSame(KeyEncryptionMethod::RSA_OAEP_MGF1P->value, $encryptionMethod->getAttribute('Algorithm'));

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
