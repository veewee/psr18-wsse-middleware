<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Encryption;

use Dom\Element;
use Phpro\ResourceStream\Factory\MemoryStream;
use Phpro\ResourceStream\ResourceStream;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\OpenSSL\Cipher;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\ExternalEncryptedDataBuilder;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\ExternalPartEncryption;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\ExternalPartSealer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\EncryptionFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPart;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;
use VeeWee\Xml\Dom\Document;

final class ExternalPartSealerTest extends TestCase
{
    private const XENC = 'http://www.w3.org/2001/04/xmlenc#';
    private const TYPE = 'http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Only';
    private const TRANSFORM = 'http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Ciphertext-Transform';

    public function test_it_seals_every_part_and_reports_one_id_per_part(): void
    {
        $document = $this->container();
        $container = $this->containerElement($document);

        $sealed = $this->sealer()->seal(
            $document,
            $container,
            $this->encryption('cid:one@example.com', 'cid:two@example.com'),
            SessionKey::fromBytes(str_repeat("\x01", 32)),
            DataEncryptionMethod::AES256_GCM,
        );

        static::assertCount(2, $sealed->parts);
        static::assertCount(2, $sealed->ids);
        static::assertCount(2, array_unique($sealed->ids));
    }

    public function test_it_appends_one_encrypted_data_element_per_part_to_the_container(): void
    {
        $document = $this->container();
        $container = $this->containerElement($document);

        $this->sealer()->seal(
            $document,
            $container,
            $this->encryption('cid:one@example.com'),
            SessionKey::fromBytes(str_repeat("\x01", 32)),
            DataEncryptionMethod::AES256_GCM,
        );

        $elements = $container->getElementsByTagNameNS(self::XENC, 'EncryptedData');
        static::assertCount(1, $elements);
        static::assertSame(self::TYPE, $elements->item(0)?->getAttribute('Type'));
    }

    public function test_a_sealed_part_carries_ciphertext_rather_than_its_plaintext(): void
    {
        $document = $this->container();
        $container = $this->containerElement($document);

        $sealed = $this->sealer()->seal(
            $document,
            $container,
            $this->encryption('cid:one@example.com'),
            SessionKey::fromBytes(str_repeat("\x01", 32)),
            DataEncryptionMethod::AES256_GCM,
        );

        $part = $sealed->parts->byReference('cid:one@example.com');
        static::assertNotNull($part);
        static::assertNotSame('the plaintext', $part->content->rewind()->getContents());
    }

    public function test_it_refuses_a_part_that_reads_zero_bytes(): void
    {
        $document = $this->container();
        $container = $this->containerElement($document);
        $consumed = MemoryStream::create();

        $this->expectException(EncryptionFailed::class);
        $this->expectExceptionMessage('An external part read zero bytes.');

        $this->sealer()->seal(
            $document,
            $container,
            new ExternalPartEncryption(
                ExternalPartList::of(new ExternalPart('cid:empty@example.com', 'application/pdf', $consumed)),
                self::TYPE,
                self::TRANSFORM,
            ),
            SessionKey::fromBytes(str_repeat("\x01", 32)),
            DataEncryptionMethod::AES256_GCM,
        );
    }

    private function sealer(): ExternalPartSealer
    {
        return new ExternalPartSealer(
            new Cipher(),
            new ExternalEncryptedDataBuilder((new WsuIdConvention())->minter()),
        );
    }

    private function encryption(string ...$references): ExternalPartEncryption
    {
        $parts = [];
        foreach ($references as $reference) {
            $parts[] = new ExternalPart($reference, 'application/pdf', $this->stream('the plaintext'));
        }

        return new ExternalPartEncryption(ExternalPartList::of(...$parts), self::TYPE, self::TRANSFORM);
    }

    private function container(): Document
    {
        return Document::fromXmlString('<Security xmlns="urn:test"/>');
    }

    private function containerElement(Document $document): Element
    {
        $element = $document->toUnsafeDocument()->documentElement;
        static::assertInstanceOf(Element::class, $element);

        return $element;
    }

    /**
     * @return ResourceStream<resource>
     */
    private function stream(string $contents): ResourceStream
    {
        return MemoryStream::create()->write($contents)->rewind();
    }
}
