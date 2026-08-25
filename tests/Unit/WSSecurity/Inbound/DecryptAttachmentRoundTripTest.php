<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Inbound;

use Phpro\ResourceStream\Factory\MemoryStream;
use Phpro\ResourceStream\ResourceStream;
use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use Soap\Psr18AttachmentsMiddleware\Attachment\Attachment;
use Soap\Psr18AttachmentsMiddleware\Storage\AttachmentStorage;
use Soap\Psr18AttachmentsMiddleware\Storage\AttachmentStorageInterface;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\AttachmentParts;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\Decrypt;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Encryption;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\EncryptionFailed;
use SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\WsseSignatureFixture;
use VeeWee\Xml\Dom\Document;

/**
 * The end-to-end proof for attachment encryption: what this package seals it opens again, byte for byte, and
 * the ways it can go wrong are refused as one uniform SecurityFault.
 *
 * A round trip is the test that matters because the framing is ours to get right on both sides. The bytes are
 * IV followed by ciphertext followed by tag, unencoded, and a disagreement about that layout looks like a
 * cipher failure rather than a framing bug.
 */
#[RequiresPhp('>= 8.4.21')]
final class DecryptAttachmentRoundTripTest extends TestCase
{
    private const XENC = 'http://www.w3.org/2001/04/xmlenc#';
    private const CID = 'invoice@example.com';
    private const BYTES = '%PDF-1.7 invoice bytes';

    public function test_it_opens_an_attachment_it_sealed(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $storage = $this->storage(self::BYTES);
        $document = $this->encrypt($fixture, $storage);

        // Outbound the part is now ciphertext, labelled opaque, and the original media type is on the element.
        $sealed = $storage->requestAttachments()->findById('<'.self::CID.'>');
        static::assertSame('application/octet-stream', $sealed->mimeType);
        static::assertNotSame(self::BYTES, $sealed->content->rewind()->getContents());

        $this->decrypt($fixture, $document, $storage);

        $opened = $storage->requestAttachments()->findById('<'.self::CID.'>');
        static::assertSame(self::BYTES, $opened->content->rewind()->getContents());
        static::assertSame('application/pdf', $opened->mimeType);
    }

    public function test_the_element_it_emits_names_the_cid_and_the_ciphertext_transform(): void
    {
        $document = $this->encrypt(WsseSignatureFixture::caSignedLeaf(), $this->storage(self::BYTES));

        $xml = $document->toXmlString();
        static::assertStringContainsString('URI="cid:'.self::CID.'"', $xml);
        static::assertStringContainsString('#Attachment-Content-Only', $xml);
        static::assertStringContainsString('#Attachment-Ciphertext-Transform', $xml);
        static::assertStringContainsString('MimeType="application/pdf"', $xml);

        // The attachment's own element carries a reference and no value: its ciphertext travels in the MIME
        // part. The Body's element beside it still carries a CipherValue, which is the point of the split.
        $external = $this->attachmentEncryptedData($document);
        static::assertCount(1, $this->childrenIn($external, 'CipherReference'));
        static::assertCount(0, $this->childrenIn($external, 'CipherValue'));
    }

    /**
     * The one xenc:EncryptedData describing the attachment, told apart by the SwA type it declares.
     */
    private function attachmentEncryptedData(Document $document): \Dom\Element
    {
        foreach ($this->elements($document, 'EncryptedData') as $element) {
            if (str_contains((string) $element->getAttribute('Type'), 'Attachment-Content-Only')) {
                return $element;
            }
        }

        static::fail('No attachment xenc:EncryptedData was emitted.');
    }

    /**
     * @return list<\Dom\Element>
     */
    private function childrenIn(\Dom\Element $element, string $localName): array
    {
        $found = [];
        foreach ($element->getElementsByTagNameNS(self::XENC, $localName) as $child) {
            $found[] = $child;
        }

        return $found;
    }

    public function test_one_encrypted_key_names_the_body_and_the_attachment_together(): void
    {
        $document = $this->encrypt(
            WsseSignatureFixture::caSignedLeaf(),
            $this->storage(self::BYTES),
            parts: [Part::body()],
        );

        // The profile wants one key whose single ReferenceList covers both, which is why the attachment work
        // joins the same operation rather than running as a second block.
        static::assertCount(1, $this->elements($document, 'EncryptedKey'));
        static::assertCount(1, $this->elements($document, 'ReferenceList'));
        static::assertCount(2, $this->elements($document, 'DataReference'));
    }

    public function test_it_can_encrypt_only_the_attachments(): void
    {
        $document = $this->encrypt(
            WsseSignatureFixture::caSignedLeaf(),
            $storage = $this->storage(self::BYTES),
            parts: [],
        );

        static::assertCount(1, $this->elements($document, 'DataReference'));
        // The Body is untouched, so encrypting attachments alone is a real configuration rather than a
        // degenerate one.
        static::assertStringContainsString('<data>x</data>', $document->toXmlString());
        static::assertNotSame(
            self::BYTES,
            $storage->requestAttachments()->findById('<'.self::CID.'>')->content->rewind()->getContents(),
        );
    }

    public function test_a_tampered_attachment_ciphertext_is_refused(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $storage = $this->storage(self::BYTES);
        $document = $this->encrypt($fixture, $storage);

        $sealed = $storage->requestAttachments()->findById('<'.self::CID.'>');
        $bytes = $sealed->content->rewind()->getContents();
        // Flip one byte inside the ciphertext. The GCM tag check is what must catch this.
        $storage->requestAttachments()->replace($sealed->withContent(
            $this->stream(substr($bytes, 0, -3).chr(ord($bytes[-3]) ^ 0xff).substr($bytes, -2)),
            'application/octet-stream',
        ));

        $this->expectException(SecurityFault::class);
        $this->decrypt($fixture, $document, $storage);
    }

    public function test_an_encrypted_attachment_is_refused_when_none_are_registered(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $this->encrypt($fixture, $this->storage(self::BYTES));

        // Never silently skipped: the message would otherwise read as fully decrypted while the caller holds
        // a file that is still ciphertext.
        $this->expectException(SecurityFault::class);
        (new Decrypt($fixture->leafKey))(
            new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()),
        );
    }

    public function test_an_attachment_the_receiver_does_not_hold_is_refused(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $this->encrypt($fixture, $this->storage(self::BYTES));

        $this->expectException(SecurityFault::class);
        $this->decrypt($fixture, $document, $this->storage(self::BYTES, 'stranger@example.com'));
    }

    public function test_a_part_that_reads_zero_bytes_is_refused(): void
    {
        $storage = new AttachmentStorage();
        $storage->requestAttachments()->add(new Attachment(
            '<'.self::CID.'>',
            'file',
            'invoice.pdf',
            'application/pdf',
            MemoryStream::create(),
        ));

        // A stream already consumed elsewhere looks exactly like this. Encrypting it would ship an empty file
        // that passes every structural check on the far side.
        //
        // EncryptionFailed and not SecurityFault: outbound is not an oracle path, so the reason may surface.
        $this->expectException(EncryptionFailed::class);
        $this->expectExceptionMessage('An external part read zero bytes.');
        $this->encrypt(WsseSignatureFixture::caSignedLeaf(), $storage);
    }

    public function test_it_refuses_to_encrypt_an_element_holding_an_xop_include(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.WsseSignatureFixture::SOAP.'"'
            .' xmlns:wsse="'.WsseSignatureFixture::WSSE.'"'
            .' xmlns:wsu="'.WsseSignatureFixture::WSU.'">'
            .'<soap:Header><wsse:Security/></soap:Header>'
            .'<soap:Body><data><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include"'
            .' href="cid:'.self::CID.'"/></data></soap:Body></soap:Envelope>'
        );

        // Encrypting the element would cover only the pointer while the file travels in the clear, and the
        // message would still satisfy a policy check for "the Body is encrypted".
        $this->expectException(EncryptionFailed::class);
        $this->expectExceptionMessage('An element carrying an xop:Include cannot be encrypted');
        (new Encryption($fixture->leafCertificate))(
            new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()),
        );
    }

    /**
     * @param list<Part>|null $parts
     */
    private function encrypt(
        WsseSignatureFixture $fixture,
        AttachmentStorageInterface $storage,
        ?array $parts = null,
    ): Document {
        $document = $fixture->envelope();

        $block = (new Encryption($fixture->leafCertificate))
            ->withAttachments(AttachmentParts::request($storage));
        if ($parts !== null) {
            $block = $block->withParts($parts);
        }

        $block(new WsseContext($document, SoapVersion::Soap12, $this->profile()));

        return $document;
    }

    private function decrypt(
        WsseSignatureFixture $fixture,
        Document $document,
        AttachmentStorageInterface $storage,
    ): void {
        (new Decrypt($fixture->leafKey))
            ->withAttachments(AttachmentParts::request($storage))(
                new WsseContext($document, SoapVersion::Soap12, $this->profile()),
            );
    }

    private function profile(): SecurityProfile
    {
        return new SecurityProfile(
            crypto: new CryptoPolicy(dataEncryptionMethod: DataEncryptionMethod::AES256_GCM),
        );
    }

    private function storage(string $contents, string $cid = self::CID): AttachmentStorageInterface
    {
        $storage = new AttachmentStorage();
        $storage->requestAttachments()->add(new Attachment(
            '<'.$cid.'>',
            'file',
            'invoice.pdf',
            'application/pdf',
            $this->stream($contents),
        ));

        return $storage;
    }

    /**
     * @return list<\Dom\Element>
     */
    private function elements(Document $document, string $localName): array
    {
        $found = [];
        foreach ($document->toUnsafeDocument()->getElementsByTagNameNS(self::XENC, $localName) as $element) {
            $found[] = $element;
        }

        return $found;
    }

    /**
     * @return ResourceStream<resource>
     */
    private function stream(string $contents): ResourceStream
    {
        return MemoryStream::create()->write($contents)->rewind();
    }
}
