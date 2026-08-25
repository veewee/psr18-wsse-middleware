<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Attachment;

use Phpro\ResourceStream\Factory\MemoryStream;
use Phpro\ResourceStream\ResourceStream;
use PHPUnit\Framework\TestCase;
use Psl\MIME\Headers;
use Soap\Psr18AttachmentsMiddleware\Attachment\Attachment;
use Soap\Psr18AttachmentsMiddleware\Exception\InvalidAttachmentHeadersException;
use Soap\Psr18AttachmentsMiddleware\Storage\AttachmentStorage;
use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\AttachmentParts;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\MalformedAttachmentHeaders;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\UnknownAttachment;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\UnsupportedAttachmentHeaderForm;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPart;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartCoverage;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;

final class AttachmentPartsTest extends TestCase
{
    public function test_it_covers_a_part_s_content_and_nothing_else(): void
    {
        $storage = new AttachmentStorage();

        static::assertSame(ExternalPartCoverage::Content, AttachmentParts::request($storage)->coverage());
        static::assertSame(ExternalPartCoverage::Content, AttachmentParts::response($storage)->coverage());
    }

    public function test_it_collects_request_attachments_as_external_parts(): void
    {
        $storage = new AttachmentStorage();
        $storage->requestAttachments()->add(
            Attachment::cid('invoice@example.com', 'file', 'invoice.pdf', $this->stream('%PDF-1.7'))
        );

        $parts = AttachmentParts::request($storage)->collect();

        static::assertCount(1, $parts);
        $part = $parts->byReference('cid:invoice@example.com');
        static::assertNotNull($part);
        static::assertSame('application/pdf', $part->mimeType);
        static::assertSame('%PDF-1.7', $part->content->getContents());
    }

    public function test_it_collects_response_attachments_when_built_for_the_response_side(): void
    {
        $storage = new AttachmentStorage();
        $storage->requestAttachments()->add(
            Attachment::cid('out@example.com', 'file', 'out.pdf', $this->stream('outbound'))
        );
        $storage->responseAttachments()->add(
            Attachment::cid('in@example.com', 'file', 'in.pdf', $this->stream('inbound'))
        );

        $parts = AttachmentParts::response($storage)->collect();

        static::assertCount(1, $parts);
        static::assertNotNull($parts->byReference('cid:in@example.com'));
        static::assertNull($parts->byReference('cid:out@example.com'));
    }

    public function test_it_rewinds_so_a_second_collect_sees_the_same_bytes(): void
    {
        $storage = new AttachmentStorage();
        $storage->requestAttachments()->add(
            Attachment::cid('invoice@example.com', 'file', 'invoice.pdf', $this->stream('%PDF-1.7'))
        );
        $parts = AttachmentParts::request($storage);

        // Sign-then-encrypt collects twice over one message: the signature reads the plaintext to
        // digest it, then encryption reads the same plaintext to seal it.
        $first = $parts->collect()->byReference('cid:invoice@example.com');
        static::assertNotNull($first);
        static::assertSame('%PDF-1.7', $first->content->getContents());

        $second = $parts->collect()->byReference('cid:invoice@example.com');
        static::assertNotNull($second);
        static::assertSame('%PDF-1.7', $second->content->getContents());
    }

    public function test_it_resolves_the_collection_on_every_call(): void
    {
        $storage = new AttachmentStorage();
        $parts = AttachmentParts::request($storage);
        $storage->requestAttachments()->add(
            Attachment::cid('first@example.com', 'file', 'first.pdf', $this->stream('first'))
        );

        static::assertCount(1, $parts->collect());

        // AttachmentsMiddleware swaps the collection between calls, so capturing it at wiring time
        // would leave this adapter holding a stale one from the second request onward.
        $storage->resetRequestAttachments();
        $storage->requestAttachments()->add(
            Attachment::cid('second@example.com', 'file', 'second.pdf', $this->stream('second'))
        );

        $collected = $parts->collect();
        static::assertCount(1, $collected);
        static::assertNotNull($collected->byReference('cid:second@example.com'));
    }

    public function test_it_replaces_an_attachment_keeping_its_identity(): void
    {
        $storage = new AttachmentStorage();
        $storage->requestAttachments()->add(
            Attachment::cid('invoice@example.com', 'file', 'invoice.pdf', $this->stream('%PDF-1.7'))
        );

        AttachmentParts::request($storage)->replace(ExternalPartList::of(
            new ExternalPart('cid:invoice@example.com', 'application/octet-stream', $this->stream('ciphertext'))
        ));

        $attachment = $storage->requestAttachments()->findById('<invoice@example.com>');
        static::assertSame('file', $attachment->name);
        static::assertSame('invoice.pdf', $attachment->filename);
        static::assertSame('application/octet-stream', $attachment->mimeType);
        static::assertSame('ciphertext', $attachment->content->getContents());
    }

    public function test_it_leaves_an_attachment_it_was_not_handed_alone(): void
    {
        $storage = new AttachmentStorage();
        $storage->responseAttachments()->add(
            Attachment::cid('sealed@example.com', 'file', 'sealed.pdf', $this->stream('ciphertext'))
        );
        $storage->responseAttachments()->add(
            Attachment::cid('clear@example.com', 'file', 'clear.pdf', $this->stream('in the clear'))
        );

        // Inbound, replace() is handed only the parts an EncryptedData actually named. An attachment
        // that arrived unencrypted must survive untouched rather than be dropped.
        AttachmentParts::response($storage)->replace(ExternalPartList::of(
            new ExternalPart('cid:sealed@example.com', 'application/pdf', $this->stream('plaintext'))
        ));

        static::assertCount(2, $storage->responseAttachments());
        static::assertSame(
            'plaintext',
            $storage->responseAttachments()->findById('<sealed@example.com>')->content->getContents()
        );
        static::assertSame(
            'in the clear',
            $storage->responseAttachments()->findById('<clear@example.com>')->content->getContents()
        );
    }

    public function test_it_gives_an_attachment_without_a_media_type_the_opaque_default(): void
    {
        $storage = new AttachmentStorage();
        $storage->requestAttachments()->add(
            new Attachment('<invoice@example.com>', 'file', 'invoice.pdf', '', $this->stream('%PDF-1.7'))
        );

        $part = AttachmentParts::request($storage)->collect()->byReference('cid:invoice@example.com');

        static::assertNotNull($part);
        static::assertSame('application/octet-stream', $part->mimeType);
    }

    public function test_it_refuses_to_replace_a_reference_it_never_supplied(): void
    {
        $storage = new AttachmentStorage();
        $storage->requestAttachments()->add(
            Attachment::cid('invoice@example.com', 'file', 'invoice.pdf', $this->stream('%PDF-1.7'))
        );

        $this->expectException(UnknownAttachment::class);
        $this->expectExceptionMessage(
            'No attachment answers the external part reference "cid:stranger@example.com".'
        );

        AttachmentParts::request($storage)->replace(ExternalPartList::of(
            new ExternalPart('cid:stranger@example.com', 'application/pdf', $this->stream('x'))
        ));
    }

    public function test_it_covers_a_part_s_metadata_as_well_when_asked_to(): void
    {
        $storage = new AttachmentStorage();

        static::assertSame(
            ExternalPartCoverage::Complete,
            AttachmentParts::request($storage, ExternalPartCoverage::Complete)->coverage()
        );
        static::assertSame(
            ExternalPartCoverage::Complete,
            AttachmentParts::response($storage, ExternalPartCoverage::Complete)->coverage()
        );
    }

    public function test_it_composes_the_canonical_header_block_ahead_of_the_bytes(): void
    {
        $storage = new AttachmentStorage();
        $storage->requestAttachments()->add(
            Attachment::cid('invoice@example.com', 'invoice', 'invoice.pdf', $this->stream('%PDF-1.7'))
        );

        $part = AttachmentParts::request($storage, ExternalPartCoverage::Complete)
            ->collect()
            ->byReference('cid:invoice@example.com');

        static::assertNotNull($part);
        static::assertSame(
            "Content-Disposition:attachment;filename=\"invoice.pdf\";name=\"invoice\"\r\n"
            ."Content-ID:<invoice@example.com>\r\n"
            ."Content-Type:application/pdf\r\n"
            .'%PDF-1.7',
            $part->content->getContents()
        );
    }

    public function test_it_composes_nothing_ahead_of_the_bytes_when_covering_content_only(): void
    {
        $storage = new AttachmentStorage();
        $storage->requestAttachments()->add(
            Attachment::cid('invoice@example.com', 'invoice', 'invoice.pdf', $this->stream('%PDF-1.7'))
        );

        $part = AttachmentParts::request($storage)->collect()->byReference('cid:invoice@example.com');

        static::assertNotNull($part);
        static::assertSame('%PDF-1.7', $part->content->getContents());
    }

    public function test_it_hands_a_cipher_the_part_s_own_octets_under_either_coverage(): void
    {
        $storage = new AttachmentStorage();
        $storage->requestAttachments()->add(
            Attachment::cid('invoice@example.com', 'invoice', 'invoice.pdf', $this->stream('%PDF-1.7'))
        );

        // A CipherReference addresses the MIME part, so what sits there is the part's own bytes whatever the
        // coverage says about the plaintext inside it. Composing here would seal the wrong octets.
        $part = AttachmentParts::request($storage, ExternalPartCoverage::Complete)
            ->collectSealed()
            ->byReference('cid:invoice@example.com');

        static::assertNotNull($part);
        static::assertSame('%PDF-1.7', $part->content->getContents());
    }

    public function test_it_refuses_to_compose_a_header_it_cannot_canonicalize(): void
    {
        $storage = new AttachmentStorage();
        $storage->requestAttachments()->add(Attachment::fromHeaders(
            Headers::fromPairs([
                ['Content-ID', '<invoice@example.com>'],
                ['Content-Type', 'application/pdf (the invoice)'],
            ]),
            $this->stream('%PDF-1.7')
        ));

        $this->expectException(UnsupportedAttachmentHeaderForm::class);
        $this->expectExceptionMessage('"Content-Type" carries a comment');

        AttachmentParts::request($storage, ExternalPartCoverage::Complete)->collect();
    }

    public function test_it_carries_the_whole_content_type_header_as_the_part_s_media_type(): void
    {
        $storage = new AttachmentStorage();
        $storage->requestAttachments()->add(Attachment::fromHeaders(
            Headers::fromPairs([
                ['Content-ID', '<report@example.com>'],
                ['Content-Type', 'application/pdf; charset=UTF-8'],
            ]),
            $this->stream('%PDF-1.7')
        ));

        $part = AttachmentParts::request($storage)->collect()->byReference('cid:report@example.com');

        static::assertNotNull($part);
        static::assertSame('application/pdf; charset=UTF-8', $part->mimeType);
    }

    public function test_it_restores_a_media_type_by_replacing_the_content_type_header(): void
    {
        $storage = new AttachmentStorage();
        $storage->responseAttachments()->add(Attachment::fromHeaders(
            Headers::fromPairs([
                ['Content-ID', '<invoice@example.com>'],
                ['Content-Type', 'application/octet-stream'],
                ['Content-Disposition', 'attachment; name="invoice"; filename="invoice.xml"'],
                ['Content-Location', 'http://example.com/invoice.xml'],
            ]),
            $this->stream('ciphertext')
        ));

        AttachmentParts::response($storage)->replace(ExternalPartList::of(
            new ExternalPart('cid:invoice@example.com', 'text/xml; charset=UTF-8', $this->stream('<invoice/>'))
        ));

        $attachment = $storage->responseAttachments()->findById('<invoice@example.com>');
        static::assertSame('text/xml; charset=UTF-8', $attachment->headers->get('Content-Type'));
        static::assertSame('text/xml', $attachment->mimeType);
        static::assertSame('http://example.com/invoice.xml', $attachment->headers->get('Content-Location'));
        static::assertSame('invoice', $attachment->name);
        static::assertSame('<invoice/>', $attachment->content->getContents());
    }

    public function test_it_restores_the_header_set_a_complete_part_carries_inside_its_octets(): void
    {
        $storage = new AttachmentStorage();
        $storage->responseAttachments()->add(Attachment::fromHeaders(
            Headers::fromPairs([
                ['Content-ID', '<invoice@example.com>'],
                ['Content-Type', 'application/octet-stream'],
            ]),
            $this->stream('ciphertext')
        ));

        AttachmentParts::response($storage, ExternalPartCoverage::Complete)->replace(ExternalPartList::of(
            new ExternalPart('cid:invoice@example.com', 'application/octet-stream', $this->stream(
                "Content-ID: <invoice@example.com>\r\n"
                ."Content-Type: application/pdf; charset=binary\r\n"
                ."Content-Disposition: attachment; name=\"invoice\"; filename=\"invoice.pdf\"\r\n"
                ."\r\n"
                .'%PDF-1.7'
            ))
        ));

        $attachment = $storage->responseAttachments()->findById('<invoice@example.com>');
        static::assertSame('%PDF-1.7', $attachment->content->getContents());
        static::assertSame('application/pdf; charset=binary', $attachment->headers->get('Content-Type'));
        static::assertSame('application/pdf', $attachment->mimeType);
        static::assertSame('invoice.pdf', $attachment->filename);
        static::assertSame('invoice', $attachment->name);
    }

    public function test_it_refuses_restored_headers_addressing_another_attachment(): void
    {
        $storage = new AttachmentStorage();
        $storage->responseAttachments()->add(
            Attachment::cid('invoice@example.com', 'file', 'invoice.pdf', $this->stream('ciphertext'))
        );

        // The Content-ID is how the reference bound a digest to this part, so letting the opened octets
        // rewrite it would undo that binding.
        $this->expectException(InvalidAttachmentHeadersException::class);
        $this->expectExceptionMessage('address attachment "<other@example.com>"');

        AttachmentParts::response($storage, ExternalPartCoverage::Complete)->replace(ExternalPartList::of(
            new ExternalPart('cid:invoice@example.com', 'application/octet-stream', $this->stream(
                "Content-ID: <other@example.com>\r\n\r\n%PDF-1.7"
            ))
        ));
    }

    public function test_it_refuses_opened_octets_that_carry_no_header_block(): void
    {
        $storage = new AttachmentStorage();
        $storage->responseAttachments()->add(
            Attachment::cid('invoice@example.com', 'file', 'invoice.pdf', $this->stream('ciphertext'))
        );

        $this->expectException(MalformedAttachmentHeaders::class);

        AttachmentParts::response($storage, ExternalPartCoverage::Complete)->replace(ExternalPartList::of(
            new ExternalPart('cid:invoice@example.com', 'application/octet-stream', $this->stream('%PDF-1.7'))
        ));
    }

    /**
     * @return ResourceStream<resource>
     */
    private function stream(string $contents): ResourceStream
    {
        return MemoryStream::create()->write($contents)->rewind();
    }
}
