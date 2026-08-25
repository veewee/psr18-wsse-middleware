<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Inbound;

use Phpro\ResourceStream\Factory\MemoryStream;
use Phpro\ResourceStream\ResourceStream;
use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use Psl\MIME\Headers;
use Soap\Psr18AttachmentsMiddleware\Attachment\Attachment;
use Soap\Psr18AttachmentsMiddleware\Storage\AttachmentStorage;
use Soap\Psr18AttachmentsMiddleware\Storage\AttachmentStorageInterface;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\AttachmentParts;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\VerifySignature;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartCoverage;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\ExternalPartSignature;
use SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\WsseSignatureFixture;
use VeeWee\Xml\Dom\Document;

/**
 * The end-to-end proof for attachment signing: a genuinely signed attachment verifies through the real signer
 * and the real verifier, and every way it can go wrong is refused as one uniform SecurityFault.
 *
 * A unit test of either half would prove much less here. The digest is over raw octets with no
 * canonicalization, so a disagreement between the two sides about what those octets are shows up as nothing
 * but a mismatch, and only signing and verifying the same bytes catches it.
 */
#[RequiresPhp('>= 8.4.21')]
final class VerifyAttachmentSignatureRoundTripTest extends TestCase
{
    private const SWA_CONTENT_TRANSFORM = 'http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform';
    private const SWA_COMPLETE_TRANSFORM = 'http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Complete-Signature-Transform';
    private const CID = 'invoice@example.com';

    public function test_it_verifies_an_attachment_the_signature_covers(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $storage = $this->storage('%PDF-1.7 invoice bytes');
        $document = $this->signWith($fixture, $storage);

        $this->verify($fixture, $document, $storage);

        // Reaching here is the pass: the block throws rather than returning a verdict.
        static::assertStringContainsString('cid:'.self::CID, $document->toXmlString());
    }

    public function test_the_reference_it_emits_names_the_cid_and_the_content_transform(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $this->signWith($fixture, $this->storage('%PDF-1.7 invoice bytes'));

        $xml = $document->toXmlString();
        static::assertStringContainsString('URI="cid:'.self::CID.'"', $xml);
        static::assertStringContainsString(self::SWA_CONTENT_TRANSFORM, $xml);
    }

    public function test_a_tampered_attachment_is_refused(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $storage = $this->storage('%PDF-1.7 invoice bytes');
        $document = $this->signWith($fixture, $storage);

        // One byte of the file changes after signing. Nothing in the XML moved.
        $storage->responseAttachments()->replace(
            $storage->responseAttachments()->findById('<'.self::CID.'>')
                ->withContent($this->stream('%PDF-1.7 invoice byteS'), 'application/pdf'),
        );

        $this->expectException(SecurityFault::class);
        $this->verify($fixture, $document, $storage);
    }

    public function test_an_attachment_the_peer_left_unsigned_is_refused(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        // Signed without any external part, so the signature says nothing about the file.
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        // Registering it on the inbound block is the requirement that it be covered.
        $this->expectException(SecurityFault::class);
        $this->verify($fixture, $document, $this->storage('%PDF-1.7 invoice bytes'));
    }

    public function test_a_reference_naming_an_attachment_that_was_not_supplied_is_refused(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $this->signWith($fixture, $this->storage('%PDF-1.7 invoice bytes'));

        // The signature covers cid:invoice@example.com; the receiver holds a different file entirely.
        $this->expectException(SecurityFault::class);
        $this->verify($fixture, $document, $this->storage('other', 'stranger@example.com'));
    }

    public function test_the_same_bytes_under_another_cid_do_not_satisfy_the_reference(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $bytes = '%PDF-1.7 invoice bytes';
        $document = $this->signWith($fixture, $this->storage($bytes));

        // Byte-identical content under a different Content-ID. A digest check alone cannot tell these apart,
        // so only binding the reference to one specific cid refuses the substitution.
        $this->expectException(SecurityFault::class);
        $this->verify($fixture, $document, $this->storage($bytes, 'substitute@example.com'));
    }

    public function test_it_verifies_a_part_whose_stream_was_already_read(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $storage = $this->storage('%PDF-1.7 invoice bytes');
        $document = $this->signWith($fixture, $storage);

        // Signing consumed the stream, and inbound the decryption block would have read it too. Verifying has
        // to start from the beginning or the digest is taken over nothing.
        $storage->responseAttachments()->findById('<'.self::CID.'>')->content->getContents();

        $this->verify($fixture, $document, $storage);

        static::assertStringContainsString('cid:'.self::CID, $document->toXmlString());
    }

    public function test_a_cid_reference_is_refused_when_no_attachments_are_registered(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $this->signWith($fixture, $this->storage('%PDF-1.7 invoice bytes'));

        // Without registered parts the standing rule applies: an external reference URI is never resolved.
        $this->expectException(SecurityFault::class);
        (new VerifySignature(TrustStore::fromCertificates($fixture->caCertificate), signed: [Part::body()]))(
            new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()),
        );
    }

    public function test_it_still_requires_the_body_alongside_the_attachment(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $storage = $this->storage('%PDF-1.7 invoice bytes');
        // Only the timestamp and the attachment are signed, so the Body requirement must still bite.
        $document = $fixture->sign(
            [WsseSignatureFixture::timestampTarget()],
            withTimestamp: true,
            externalParts: new ExternalPartSignature(
                AttachmentParts::response($storage)->collect(),
                self::SWA_CONTENT_TRANSFORM,
            ),
        );

        $this->expectException(SecurityFault::class);
        $this->verify($fixture, $document, $storage);
    }

    public function test_it_verifies_an_attachment_whose_headers_the_signature_covers_too(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $storage = $this->storage('%PDF-1.7 invoice bytes');
        $document = $this->signWith($fixture, $storage, ExternalPartCoverage::Complete);

        $this->verify($fixture, $document, $storage, ExternalPartCoverage::Complete);

        static::assertStringContainsString(self::SWA_COMPLETE_TRANSFORM, $document->toXmlString());
    }

    public function test_a_header_changed_after_signing_is_refused_under_a_complete_coverage(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $storage = $this->storage('%PDF-1.7 invoice bytes');
        $document = $this->signWith($fixture, $storage, ExternalPartCoverage::Complete);

        // Not a byte of the file changes; only the name it travelled under does. A content-only coverage
        // would not notice.
        $storage->responseAttachments()->replace(
            $storage->responseAttachments()->findById('<'.self::CID.'>')
                ->withHeaders(Headers::fromPairs([
                    ['Content-ID', '<'.self::CID.'>'],
                    ['Content-Type', 'application/pdf'],
                    ['Content-Disposition', 'attachment; name="file"; filename="paid.pdf"'],
                ])),
        );

        $this->expectException(SecurityFault::class);
        $this->verify($fixture, $document, $storage, ExternalPartCoverage::Complete);
    }

    public function test_a_content_only_reference_is_refused_by_a_complete_adapter(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $storage = $this->storage('%PDF-1.7 invoice bytes');
        $document = $this->signWith($fixture, $storage);

        // The coverage a peer declares is a requirement rather than a hint, which is what the Java side
        // does to us in the other direction. Asserting the reason rather than the type: every inbound
        // failure is the same type, so a digest mismatch would satisfy the type alone.
        $this->assertRefusedBecause(
            'A reference declares an unsupported transform.',
            fn (): mixed => $this->verify($fixture, $document, $storage, ExternalPartCoverage::Complete),
        );
    }

    public function test_a_complete_reference_is_refused_by_a_content_only_adapter(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $storage = $this->storage('%PDF-1.7 invoice bytes');
        $document = $this->signWith($fixture, $storage, ExternalPartCoverage::Complete);

        $this->assertRefusedBecause(
            'A reference declares an unsupported transform.',
            fn (): mixed => $this->verify($fixture, $document, $storage),
        );
    }

    /**
     * @param callable(): mixed $verification
     */
    private function assertRefusedBecause(string $reason, callable $verification): void
    {
        try {
            $verification();
        } catch (SecurityFault $fault) {
            static::assertSame($reason, $fault->getPrevious()?->getMessage());

            return;
        }

        static::fail('The message was accepted.');
    }

    private function signWith(
        WsseSignatureFixture $fixture,
        AttachmentStorageInterface $storage,
        ExternalPartCoverage $coverage = ExternalPartCoverage::Content,
    ): Document {
        return $fixture->sign(
            [WsseSignatureFixture::bodyTarget()],
            externalParts: new ExternalPartSignature(
                AttachmentParts::response($storage, $coverage)->collect(),
                $coverage === ExternalPartCoverage::Complete
                    ? self::SWA_COMPLETE_TRANSFORM
                    : self::SWA_CONTENT_TRANSFORM,
            ),
        );
    }

    private function verify(
        WsseSignatureFixture $fixture,
        Document $document,
        AttachmentStorageInterface $storage,
        ExternalPartCoverage $coverage = ExternalPartCoverage::Content,
    ): void {
        (new VerifySignature(TrustStore::fromCertificates($fixture->caCertificate), signed: [Part::body()]))
            ->withAttachments(AttachmentParts::response($storage, $coverage))(
                new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()),
            );
    }

    private function storage(string $contents, string $cid = self::CID): AttachmentStorageInterface
    {
        $storage = new AttachmentStorage();
        $storage->responseAttachments()->add(new Attachment(
            '<'.$cid.'>',
            'file',
            'invoice.pdf',
            'application/pdf',
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
