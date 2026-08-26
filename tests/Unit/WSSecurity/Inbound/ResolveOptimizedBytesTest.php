<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Inbound;

use Phpro\ResourceStream\Factory\MemoryStream;
use Phpro\ResourceStream\ResourceStream;
use PHPUnit\Framework\TestCase;
use Soap\Psr18AttachmentsMiddleware\Attachment\Attachment;
use Soap\Psr18AttachmentsMiddleware\Attachment\Cid;
use Soap\Psr18AttachmentsMiddleware\Storage\AttachmentStorage;
use Soap\Psr18AttachmentsMiddleware\Storage\AttachmentStorageInterface;
use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\AttachmentParts;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\ResolveOptimizedBytes;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\ExchangeKeys;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartCoverage;
use VeeWee\Xml\Dom\Document;

/**
 * The inbound pre-pass for peers that put cipher bytes in a MIME part instead of base64-inlining them.
 *
 * A .NET, Metro or MTOM-enabled CXF peer does this to any large encrypted content without negotiating it, so
 * what arrives is an xop:Include where a value belongs. This block puts the bytes back where the message says
 * they belong and every reader downstream stays unchanged, which is exactly what a peer does with the same
 * message.
 *
 * Because the peers switch on a size threshold, one message routinely mixes both shapes. Resolution is
 * therefore per element, never per message.
 */
final class ResolveOptimizedBytesTest extends TestCase
{
    private const XOP = 'http://www.w3.org/2004/08/xop/include';
    private const SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const XENC = 'http://www.w3.org/2001/04/xmlenc#';
    private const CID = 'cipher-1@example.com';
    private const BYTES = "\x00\x01\x02raw cipher bytes\xff";

    public function test_it_puts_the_bytes_of_an_optimized_encrypted_data_back_in_the_document(): void
    {
        $document = $this->envelope(body: $this->encryptedData($this->pointer(self::CID)));

        $this->resolve($document, $this->storage(self::BYTES));

        static::assertStringContainsString(
            '<xenc:CipherValue>'.base64_encode(self::BYTES).'</xenc:CipherValue>',
            $document->toXmlString(),
        );
    }

    public function test_it_puts_the_bytes_of_an_optimized_encrypted_key_back_in_the_document(): void
    {
        $document = $this->envelope(header: $this->encryptedKey($this->pointer(self::CID)));

        $this->resolve($document, $this->storage(self::BYTES));

        static::assertStringContainsString(base64_encode(self::BYTES), $document->toXmlString());
    }

    public function test_it_puts_the_bytes_of_an_optimized_binary_security_token_back_in_the_document(): void
    {
        $document = $this->envelope(
            header: '<wsse:BinarySecurityToken xmlns:wsse="'.self::WSSE.'">'
                .$this->pointer(self::CID)
                .'</wsse:BinarySecurityToken>',
        );

        $this->resolve($document, $this->storage(self::BYTES));

        static::assertStringContainsString(base64_encode(self::BYTES), $document->toXmlString());
    }

    public function test_it_resolves_one_element_and_leaves_the_inline_one_beside_it_alone(): void
    {
        // The shape a size threshold actually produces: the wrapped key is small enough to stay inline while
        // the body's cipher bytes move to a part.
        $document = $this->envelope(
            header: $this->encryptedKey('<xenc:CipherValue>aW5saW5l</xenc:CipherValue>'),
            body: $this->encryptedData($this->pointer(self::CID)),
        );

        $this->resolve($document, $this->storage(self::BYTES));

        $xml = $document->toXmlString();
        static::assertStringContainsString('<xenc:CipherValue>aW5saW5l</xenc:CipherValue>', $xml);
        static::assertStringContainsString(base64_encode(self::BYTES), $xml);
    }

    public function test_a_message_carrying_no_pointer_passes_through_untouched(): void
    {
        // Registering the block is not a requirement that the shape be present: the peer's threshold decides
        // per message, so requiring it would refuse valid traffic.
        $document = $this->envelope(body: $this->encryptedData('<xenc:CipherValue>aW5saW5l</xenc:CipherValue>'));
        $before = $document->toXmlString();

        $this->resolve($document, $this->storage(self::BYTES));

        static::assertSame($before, $document->toXmlString());
    }

    public function test_it_leaves_a_pointer_that_is_not_standing_in_for_a_security_value_alone(): void
    {
        // An ordinary MTOM-optimized body element is the attachments middleware's business, not this block's.
        $document = $this->envelope(body: '<data>'.$this->pointer(self::CID).'</data>');
        $before = $document->toXmlString();

        $this->resolve($document, $this->storage(self::BYTES));

        static::assertSame($before, $document->toXmlString());
    }

    public function test_the_xop_encoder_can_still_resolve_its_own_attachment_afterwards(): void
    {
        // The attachments package decodes an MTOM response element by doing exactly
        // responseAttachments()->findById(Cid::idFor($href)), which throws when the part is gone. So this
        // block has to leave an application-level include and its part exactly where the encoder expects
        // them, while resolving the security value beside it.
        $storage = $this->storage(self::BYTES);
        $storage->responseAttachments()->add(new Attachment(
            '<invoice@example.com>',
            'file',
            'invoice.pdf',
            'application/pdf',
            $this->stream('%PDF-1.7 invoice bytes'),
        ));

        $document = $this->envelope(
            body: '<message>'.$this->pointer('invoice@example.com').'</message>'
                .$this->encryptedData($this->pointer(self::CID)),
        );

        $this->resolve($document, $storage);

        static::assertStringContainsString(
            'href="'.Cid::uriFor('<invoice@example.com>').'"',
            $document->toXmlString(),
            "the encoder's own pointer must survive untouched",
        );
        static::assertSame(
            '%PDF-1.7 invoice bytes',
            $storage->responseAttachments()
                ->findById(Cid::idFor(Cid::uriFor('<invoice@example.com>')))
                ->content->rewind()->getContents(),
        );
        static::assertStringContainsString(base64_encode(self::BYTES), $document->toXmlString());
    }

    public function test_it_leaves_the_consumed_part_in_the_collection(): void
    {
        // Documented rather than tidied: removing it would need a capability the seam does not have, and only
        // a caller who deliberately wired this block ever sees the leftover.
        $storage = $this->storage(self::BYTES);
        $document = $this->envelope(body: $this->encryptedData($this->pointer(self::CID)));

        $this->resolve($document, $storage);

        static::assertCount(1, $storage->responseAttachments());
    }

    public function test_a_pointer_naming_no_supplied_part_is_refused(): void
    {
        $document = $this->envelope(body: $this->encryptedData($this->pointer('other@example.com')));

        $this->assertRefusedBecause(
            'A security value points at content that was not supplied.',
            fn (): mixed => $this->resolve($document, $this->storage(self::BYTES)),
        );
    }

    public function test_a_pointer_at_an_absolute_uri_is_refused_rather_than_fetched(): void
    {
        $document = $this->envelope(
            body: $this->encryptedData(
                '<xop:Include xmlns:xop="'.self::XOP.'" href="https://example.com/bytes"/>',
            ),
        );

        $this->assertRefusedBecause(
            'A security value points at content that was not supplied.',
            fn (): mixed => $this->resolve($document, $this->storage(self::BYTES)),
        );
    }

    public function test_two_pointers_in_one_value_are_refused(): void
    {
        $document = $this->envelope(
            body: $this->encryptedData($this->pointer(self::CID).$this->pointer(self::CID)),
        );

        $this->assertRefusedBecause(
            'A security value describes its content two ways at once.',
            fn (): mixed => $this->resolve($document, $this->storage(self::BYTES)),
        );
    }

    public function test_a_pointer_beside_text_is_refused(): void
    {
        $document = $this->envelope(body: $this->encryptedData('aW5saW5l'.$this->pointer(self::CID)));

        $this->assertRefusedBecause(
            'A security value describes its content two ways at once.',
            fn (): mixed => $this->resolve($document, $this->storage(self::BYTES)),
        );
    }

    public function test_a_pointer_nested_below_the_value_is_refused(): void
    {
        $document = $this->envelope(
            body: $this->encryptedData('<wrap>'.$this->pointer(self::CID).'</wrap>'),
        );

        $this->assertRefusedBecause(
            'A security value describes its content two ways at once.',
            fn (): mixed => $this->resolve($document, $this->storage(self::BYTES)),
        );
    }

    public function test_a_pointer_naming_nothing_is_refused(): void
    {
        $document = $this->envelope(
            body: $this->encryptedData('<xop:Include xmlns:xop="'.self::XOP.'"/>'),
        );

        $this->assertRefusedBecause(
            'A security value describes its content two ways at once.',
            fn (): mixed => $this->resolve($document, $this->storage(self::BYTES)),
        );
    }

    public function test_a_message_declaring_more_pointers_than_the_cap_is_refused_before_any_part_is_read(): void
    {
        $body = '';
        for ($i = 0; $i <= ResolveOptimizedBytes::MAX_OPTIMIZED_ELEMENTS; ++$i) {
            $body .= $this->encryptedData($this->pointer(self::CID));
        }

        $this->assertRefusedBecause(
            'The message points at more content than it is allowed to.',
            fn (): mixed => $this->resolve($this->envelope(body: $body), $this->storage(self::BYTES)),
        );
    }

    public function test_an_empty_part_is_left_for_the_reader_that_already_refuses_it(): void
    {
        // No second gate here: the decryptor's own length check refuses it, and one more distinguishable
        // outcome on that path is exactly what a padding oracle is made of.
        $document = $this->envelope(body: $this->encryptedData($this->pointer(self::CID)));

        $this->resolve($document, $this->storage(''));

        static::assertStringContainsString(
            '<xenc:CipherValue></xenc:CipherValue>',
            $document->toXmlString(),
        );
    }

    /**
     * @param callable(): mixed $resolution
     */
    private function assertRefusedBecause(string $reason, callable $resolution): void
    {
        try {
            $resolution();
        } catch (SecurityFault $fault) {
            static::assertSame($reason, $fault->getPrevious()?->getMessage());

            return;
        }

        static::fail('The message was accepted.');
    }

    private function resolve(Document $document, AttachmentStorageInterface $storage): void
    {
        (new ResolveOptimizedBytes(
            AttachmentParts::response($storage, ExternalPartCoverage::Content),
        ))(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile(), new ExchangeKeys()));
    }

    private function pointer(string $cid): string
    {
        return '<xop:Include xmlns:xop="'.self::XOP.'" href="cid:'.$cid.'"/>';
    }

    private function encryptedData(string $cipherValue): string
    {
        return '<xenc:EncryptedData xmlns:xenc="'.self::XENC.'">'
            .'<xenc:CipherData>'.$this->cipherValue($cipherValue).'</xenc:CipherData>'
            .'</xenc:EncryptedData>';
    }

    private function encryptedKey(string $cipherValue): string
    {
        return '<xenc:EncryptedKey xmlns:xenc="'.self::XENC.'">'
            .'<xenc:CipherData>'.$this->cipherValue($cipherValue).'</xenc:CipherData>'
            .'</xenc:EncryptedKey>';
    }

    /**
     * The markup a test hands in is either a whole xenc:CipherValue or the content to wrap in one.
     */
    private function cipherValue(string $contents): string
    {
        return str_starts_with($contents, '<xenc:CipherValue')
            ? $contents
            : '<xenc:CipherValue>'.$contents.'</xenc:CipherValue>';
    }

    private function envelope(string $header = '', string $body = '<data>x</data>'): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP.'">'
            .'<soap:Header><wsse:Security xmlns:wsse="'.self::WSSE.'">'.$header.'</wsse:Security></soap:Header>'
            .'<soap:Body>'.$body.'</soap:Body>'
            .'</soap:Envelope>',
        );
    }

    private function storage(string $contents, string $cid = self::CID): AttachmentStorageInterface
    {
        $storage = new AttachmentStorage();
        $storage->responseAttachments()->add(new Attachment(
            '<'.$cid.'>',
            'cipher',
            'cipher',
            'application/ciphervalue',
            $this->stream($contents),
        ));

        return $storage;
    }

    /**
     * @return ResourceStream<resource>
     */
    private function stream(string $contents): ResourceStream
    {
        return MemoryStream::create()->write($contents)->rewind();
    }
}
