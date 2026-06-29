<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\XmlSec\Default;

use Dom\Element;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\OpenSSL\Cipher;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\DecryptionFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Manipulator\WsuIdMinter;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\EncryptedDataBuilder;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\EncryptedDataReader;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\EncryptionMode;
use VeeWee\Xml\Dom\Document;

/**
 * Round-trips the CipherValue framing through the real OpenSSL\Cipher for both GCM and CBC, then exercises the
 * security failure arms: a truncated tag, a tampered ciphertext and malformed base64 must all collapse to the
 * one uniform DecryptionFailed type with no distinguishing detail.
 */
final class EncryptedDataRoundTripTest extends TestCase
{
    private const SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    private const APP = 'urn:app';
    private const XENC = 'http://www.w3.org/2001/04/xmlenc#';

    /**
     * @return iterable<string, array{0: DataEncryptionMethod, 1: int}>
     */
    public static function methods(): iterable
    {
        yield 'aes-256-gcm' => [DataEncryptionMethod::AES256_GCM, 32];
        yield 'aes-128-gcm' => [DataEncryptionMethod::AES128_GCM, 16];
        yield 'aes-256-cbc' => [DataEncryptionMethod::AES256_CBC, 32];
        yield 'aes-128-cbc' => [DataEncryptionMethod::AES128_CBC, 16];
    }

    #[DataProvider('methods')]
    public function test_it_round_trips_content_mode(DataEncryptionMethod $method, int $keyLength): void
    {
        $key = SessionKey::fromBytes(str_repeat("\x01", $keyLength));
        $document = $this->envelope();
        $body = $this->body($document);

        $original = $this->innerXml($body);

        $cipherText = (new Cipher())->encrypt($original, $key, $method);
        (new EncryptedDataBuilder(new WsuIdMinter()))->build($document, $body, $cipherText, $method, EncryptionMode::Content);

        $encryptedData = $this->onlyEncryptedData($document);
        (new EncryptedDataReader(new Cipher()))->read($document, $encryptedData, $key);

        static::assertSame($original, $this->innerXml($this->body($document)));
    }

    #[DataProvider('methods')]
    public function test_it_round_trips_element_mode(DataEncryptionMethod $method, int $keyLength): void
    {
        $key = SessionKey::fromBytes(str_repeat("\x02", $keyLength));
        $document = $this->envelope();
        $custom = $this->custom($document);

        $original = $document->stringifyNode($custom);

        $cipherText = (new Cipher())->encrypt($original, $key, $method);
        (new EncryptedDataBuilder(new WsuIdMinter()))->build($document, $custom, $cipherText, $method, EncryptionMode::Element);

        $encryptedData = $this->onlyEncryptedData($document);
        (new EncryptedDataReader(new Cipher()))->read($document, $encryptedData, $key);

        static::assertStringContainsString('<app:Custom', $document->toXmlString());
        static::assertStringContainsString('payload', $document->toXmlString());
        static::assertStringNotContainsString('EncryptedData', $document->toXmlString());
    }

    public function test_a_truncated_gcm_tag_is_rejected_before_decrypt(): void
    {
        $key = SessionKey::fromBytes(str_repeat("\x03", 32));
        $document = $this->envelope();
        $body = $this->body($document);

        $cipherText = (new Cipher())->encrypt('<a/>', $key, DataEncryptionMethod::AES256_GCM);
        // Truncate the tag inside the framing by chopping the final byte from the framed blob.
        $framed = $cipherText->iv.$cipherText->bytes.substr((string) $cipherText->tag, 0, -1);

        $document = $this->envelope();
        $body = $this->body($document);
        $this->placeEncryptedData($document, $body, base64_encode($framed), DataEncryptionMethod::AES256_GCM);

        $this->expectException(DecryptionFailed::class);
        (new EncryptedDataReader(new Cipher()))->read($document, $this->onlyEncryptedData($document), $key);
    }

    public function test_a_tampered_gcm_ciphertext_is_rejected(): void
    {
        $key = SessionKey::fromBytes(str_repeat("\x04", 32));
        $document = $this->envelope();
        $body = $this->body($document);

        $cipherText = (new Cipher())->encrypt('<a>secret</a>', $key, DataEncryptionMethod::AES256_GCM);
        $tamperedBytes = $cipherText->bytes;
        $tamperedBytes[0] = $tamperedBytes[0] === "\x00" ? "\x01" : "\x00";
        $framed = $cipherText->iv.$tamperedBytes.(string) $cipherText->tag;

        $this->placeEncryptedData($document, $body, base64_encode($framed), DataEncryptionMethod::AES256_GCM);

        $this->expectException(DecryptionFailed::class);
        (new EncryptedDataReader(new Cipher()))->read($document, $this->onlyEncryptedData($document), $key);
    }

    public function test_malformed_base64_is_rejected(): void
    {
        $document = $this->envelope();
        $body = $this->body($document);
        $this->placeEncryptedData($document, $body, 'not valid base64 ###', DataEncryptionMethod::AES256_GCM);

        $this->expectException(DecryptionFailed::class);
        (new EncryptedDataReader(new Cipher()))->read($document, $this->onlyEncryptedData($document), SessionKey::fromBytes(str_repeat("\x05", 32)));
    }

    public function test_a_doctype_in_the_decrypted_plaintext_is_rejected(): void
    {
        $key = SessionKey::fromBytes(str_repeat("\x08", 32));
        $document = $this->envelope();
        $body = $this->body($document);

        // A genuine GCM round-trip whose recovered plaintext carries a DOCTYPE: the cipher recovers it, but the
        // re-parse of the attacker-influenced fragment must refuse it and collapse to the uniform failure.
        $plaintext = '<!DOCTYPE x [<!ENTITY a "b">]><a>secret</a>';
        $cipherText = (new Cipher())->encrypt($plaintext, $key, DataEncryptionMethod::AES256_GCM);
        $framed = $cipherText->iv.$cipherText->bytes.(string) $cipherText->tag;
        $this->placeEncryptedData($document, $body, base64_encode($framed), DataEncryptionMethod::AES256_GCM);

        $this->expectException(DecryptionFailed::class);
        (new EncryptedDataReader(new Cipher()))->read($document, $this->onlyEncryptedData($document), $key);
    }

    public function test_bad_cbc_padding_and_wrong_key_share_the_same_failure(): void
    {
        // A corrupted CBC block and a wrong key must both surface one identical exception type and message, so
        // neither acts as a distinguisher. CBC decryption only fails probabilistically (a random block has a
        // ~1/256 chance of yielding valid padding), so each case retries with a fresh random IV until it does
        // fail; the assertion is on the uniform failure, not on any single attempt.
        $wrongKeyError = $this->captureCbcDecryptFailure(
            SessionKey::fromBytes(str_repeat("\x07", 32)),
            static fn (string $bytes): string => $bytes,
        );
        $badPaddingError = $this->captureCbcDecryptFailure(
            SessionKey::fromBytes(str_repeat("\x06", 32)),
            $this->corruptLastByte(...),
        );

        static::assertSame($wrongKeyError::class, $badPaddingError::class);
        static::assertSame($wrongKeyError->getMessage(), $badPaddingError->getMessage());
    }

    /**
     * Encrypts a known plaintext with the canonical key, applies the mutation, and decrypts with the given
     * key, retrying with a fresh IV until the decryption genuinely fails so the test never flakes on a
     * coincidentally valid padding.
     *
     * @param callable(string): string $mutate
     */
    private function captureCbcDecryptFailure(SessionKey $decryptKey, callable $mutate): DecryptionFailed
    {
        for ($attempt = 0; $attempt < 16; $attempt++) {
            $document = $this->envelope();
            $cipherText = (new Cipher())->encrypt('<a>secret</a>', SessionKey::fromBytes(str_repeat("\x06", 32)), DataEncryptionMethod::AES256_CBC);
            $framed = base64_encode($cipherText->iv.$mutate($cipherText->bytes));
            $this->placeEncryptedData($document, $this->body($document), $framed, DataEncryptionMethod::AES256_CBC);
            $encryptedData = $this->onlyEncryptedData($document);

            try {
                (new EncryptedDataReader(new Cipher()))->read($document, $encryptedData, $decryptKey);
            } catch (DecryptionFailed $exception) {
                return $exception;
            }
        }

        static::fail('The CBC decryption did not fail within the attempt budget.');
    }

    private function corruptLastByte(string $bytes): string
    {
        $last = strlen($bytes) - 1;
        $bytes[$last] = $bytes[$last] === "\x00" ? "\x01" : "\x00";

        return $bytes;
    }

    private function placeEncryptedData(Document $document, Element $body, string $cipherValue, DataEncryptionMethod $method): void
    {
        while ($body->firstChild !== null) {
            $body->removeChild($body->firstChild);
        }

        $dom = $document->toUnsafeDocument();
        $encryptedData = $dom->createElementNS(self::XENC, 'xenc:EncryptedData');
        $encryptedData->setAttribute('Type', EncryptionMode::Content->value);
        $encryptedData->setAttributeNS(
            'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
            'wsu:Id',
            'id-test',
        );
        $em = $dom->createElementNS(self::XENC, 'xenc:EncryptionMethod');
        $em->setAttribute('Algorithm', $method->value);
        $cipherData = $dom->createElementNS(self::XENC, 'xenc:CipherData');
        $cv = $dom->createElementNS(self::XENC, 'xenc:CipherValue');
        $cv->textContent = $cipherValue;
        $cipherData->appendChild($cv);
        $encryptedData->appendChild($em);
        $encryptedData->appendChild($cipherData);
        $body->appendChild($encryptedData);
    }

    private function envelope(): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP.'" xmlns:app="'.self::APP.'">'
            .'<soap:Header><app:Custom>payload<app:inner>x</app:inner></app:Custom></soap:Header>'
            .'<soap:Body><app:Op><app:n>5</app:n>text</app:Op></soap:Body>'
            .'</soap:Envelope>',
        );
    }

    private function body(Document $document): Element
    {
        $body = $document->toUnsafeDocument()->getElementsByTagNameNS(self::SOAP, 'Body')->item(0);
        static::assertInstanceOf(Element::class, $body);

        return $body;
    }

    private function custom(Document $document): Element
    {
        $custom = $document->toUnsafeDocument()->getElementsByTagNameNS(self::APP, 'Custom')->item(0);
        static::assertInstanceOf(Element::class, $custom);

        return $custom;
    }

    private function onlyEncryptedData(Document $document): Element
    {
        $nodes = $document->toUnsafeDocument()->getElementsByTagNameNS(self::XENC, 'EncryptedData');
        $first = $nodes->item(0);
        static::assertInstanceOf(Element::class, $first);

        return $first;
    }

    private function innerXml(Element $element): string
    {
        $inner = '';
        foreach ($element->childNodes as $child) {
            $inner .= $element->ownerDocument->saveXML($child);
        }

        return $inner;
    }
}
