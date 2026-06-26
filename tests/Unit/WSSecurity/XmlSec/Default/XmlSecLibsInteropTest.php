<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\XmlSec\Default;

use Dom\Element;
use DOMDocument;
use DOMElement;
use PHPUnit\Framework\TestCase;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use Soap\Psr18WsseMiddleware\OpenSSL\Cipher;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Wsse\WsuIdMinter;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Default\EncryptedDataBuilder;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Default\EncryptedDataReader;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Default\EncryptionMode;
use VeeWee\Xml\Dom\Document;

/**
 * Cross-stack proof that the B5 CipherValue framing is the canonical on-wire layout: a reference
 * implementation (xmlseclibs) decrypts an EncryptedData B5 produced, and B5 decrypts an EncryptedData
 * xmlseclibs produced. Both directions exercise the IV || ciphertext [|| tag] framing for AES-256-CBC.
 */
final class XmlSecLibsInteropTest extends TestCase
{
    private const SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    private const APP = 'urn:app';
    private const XENC = 'http://www.w3.org/2001/04/xmlenc#';

    public function test_xmlseclibs_decrypts_a_b5_encrypted_element(): void
    {
        $sessionKey = str_repeat("\x09", 32);
        $document = $this->envelope();
        $custom = $this->custom($document);
        $original = $document->stringifyNode($custom);

        $cipherText = (new Cipher())->encrypt($original, $sessionKey, DataEncryptionMethod::AES256_CBC);
        (new EncryptedDataBuilder(new WsuIdMinter()))->build($document, $custom, $cipherText, DataEncryptionMethod::AES256_CBC, EncryptionMode::Element);

        // Hand the serialized EncryptedData to xmlseclibs and decrypt with the raw session key.
        $dom = new DOMDocument();
        static::assertTrue($dom->loadXML($document->toXmlString()));
        $encryptedDataNode = $dom->getElementsByTagNameNS(self::XENC, 'EncryptedData')->item(0);
        static::assertInstanceOf(DOMElement::class, $encryptedDataNode);

        $enc = new XMLSecEnc();
        $enc->setNode($encryptedDataNode);
        $enc->type = XMLSecEnc::Element;

        $key = new XMLSecurityKey(XMLSecurityKey::AES256_CBC);
        $key->loadKey($sessionKey);

        $decrypted = $enc->decryptNode($key, false);
        static::assertIsString($decrypted);
        static::assertStringContainsString('payload', $decrypted);
    }

    public function test_b5_decrypts_an_xmlseclibs_encrypted_element(): void
    {
        $sessionKey = str_repeat("\x0a", 32);

        $dom = new DOMDocument();
        static::assertTrue($dom->loadXML('<app:Custom xmlns:app="'.self::APP.'">payload<app:inner>deep</app:inner></app:Custom>'));

        $key = new XMLSecurityKey(XMLSecurityKey::AES256_CBC);
        $key->loadKey($sessionKey);

        $enc = new XMLSecEnc();
        $enc->setNode($dom->documentElement);
        $enc->type = XMLSecEnc::Element;
        $encryptedNode = $enc->encryptNode($key);
        static::assertInstanceOf(DOMElement::class, $encryptedNode);

        // Re-host the xmlseclibs EncryptedData inside a B5 document with a wsu:Id and let the reader restore it.
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP.'"><soap:Body>'.$dom->saveXML($encryptedNode).'</soap:Body></soap:Envelope>',
        );
        $encryptedData = $document->toUnsafeDocument()->getElementsByTagNameNS(self::XENC, 'EncryptedData')->item(0);
        static::assertInstanceOf(Element::class, $encryptedData);

        (new EncryptedDataReader(new Cipher()))->read($document, $encryptedData, $sessionKey);

        static::assertStringContainsString('<app:Custom', $document->toXmlString());
        static::assertStringContainsString('payload', $document->toXmlString());
        static::assertStringNotContainsString('EncryptedData', $document->toXmlString());
    }

    private function envelope(): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP.'" xmlns:app="'.self::APP.'">'
            .'<soap:Header><app:Custom>payload<app:inner>deep</app:inner></app:Custom></soap:Header>'
            .'<soap:Body><data>x</data></soap:Body>'
            .'</soap:Envelope>',
        );
    }

    private function custom(Document $document): Element
    {
        $custom = $document->toUnsafeDocument()->getElementsByTagNameNS(self::APP, 'Custom')->item(0);
        static::assertInstanceOf(Element::class, $custom);

        return $custom;
    }
}
