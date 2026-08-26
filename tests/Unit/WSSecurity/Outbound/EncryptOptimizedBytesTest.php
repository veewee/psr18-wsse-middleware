<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound;

use Dom\Element;
use Phpro\ResourceStream\Factory\MemoryStream;
use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use Soap\Psr18AttachmentsMiddleware\Attachment\Attachment;
use Soap\Psr18AttachmentsMiddleware\Storage\AttachmentStorage;
use Soap\Psr18AttachmentsMiddleware\Storage\AttachmentStorageInterface;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\AttachmentParts;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\Decrypt;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\ResolveOptimizedBytes;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\ExchangeKeys;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\GeneratedSessionKey;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Encryption;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SigningFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartCoverage;
use SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\WsseSignatureFixture;
use VeeWee\Xml\Dom\Document;

/**
 * Emitting cipher bytes as MIME parts instead of base64-inlining them, which is what a WSS4J or CXF peer with
 * storeBytesInAttachment on does.
 *
 * Nothing can require this of us: it saves the 33% base64 costs and no policy assertion expresses it. It is
 * supported because the peers that send it also read it, unconditionally, so a deployment moving large
 * payloads can turn it on in both directions.
 *
 * The shapes are asserted on the wire rather than only round-tripped, because a peer has to be able to read
 * what we write and only the wire says what we wrote.
 */
#[RequiresPhp('>= 8.4.21')]
final class EncryptOptimizedBytesTest extends TestCase
{
    private const XENC = 'http://www.w3.org/2001/04/xmlenc#';
    private const XOP = 'http://www.w3.org/2004/08/xop/include';
    private const PLAINTEXT = 'the body we are sending';

    public function test_it_leaves_a_pointer_where_each_cipher_value_would_have_been(): void
    {
        $storage = new AttachmentStorage();
        $document = $this->encrypt($storage);

        foreach ($this->cipherValues($document) as $cipherValue) {
            static::assertSame('', trim($cipherValue->textContent));
            static::assertCount(1, $cipherValue->getElementsByTagNameNS(self::XOP, 'Include'));
        }
    }

    public function test_it_mints_one_part_per_cipher_value(): void
    {
        $storage = new AttachmentStorage();
        $document = $this->encrypt($storage);

        // The wrapped key and the body cipher value: two values, two parts.
        static::assertCount(2, $storage->requestAttachments());
        static::assertCount(2, $this->cipherValues($document));
    }

    public function test_the_minted_part_carries_the_media_type_a_peer_expects(): void
    {
        $storage = new AttachmentStorage();
        $this->encrypt($storage);

        foreach ($storage->requestAttachments() as $attachment) {
            static::assertSame('application/ciphervalue', $attachment->mimeType);
        }
    }

    public function test_the_minted_part_carries_the_raw_bytes_rather_than_base64(): void
    {
        $storage = new AttachmentStorage();
        $document = $this->encrypt($storage);

        $referenced = [];
        foreach ($storage->requestAttachments() as $attachment) {
            $referenced[] = 'cid:'.trim($attachment->id, '<>');
            $bytes = $attachment->content->rewind()->getContents();
            static::assertNotSame($bytes, base64_encode(base64_decode($bytes, true) ?: ''));
        }

        // Every pointer names one of the parts that were minted, verbatim.
        foreach ($this->pointers($document) as $href) {
            static::assertContains($href, $referenced);
        }
    }

    public function test_what_it_emits_is_what_it_reads(): void
    {
        $storage = new AttachmentStorage();
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $this->encrypt($storage, $fixture);

        // The parts leave in the request collection and arrive in the response one, so the round trip moves
        // them the way the transport would.
        foreach ($storage->requestAttachments() as $attachment) {
            $storage->responseAttachments()->add($attachment);
        }

        (new ResolveOptimizedBytes(
            AttachmentParts::response($storage, ExternalPartCoverage::Content),
        ))(new WsseContext($document, SoapVersion::Soap12, $this->profile(), new ExchangeKeys()));

        (new Decrypt($fixture->leafKey))(
            new WsseContext($document, SoapVersion::Soap12, $this->profile(), new ExchangeKeys()),
        );

        static::assertStringContainsString(self::PLAINTEXT, $document->toXmlString());
    }

    public function test_it_coexists_with_an_attachment_the_xop_encoder_wrote(): void
    {
        // Under MTOM the encoder has already put the file in requestAttachments and an xop:Include in the
        // Body by the time this block runs. Emission adds parts of its own beside it, so the encoder's
        // attachment has to come out of this untouched and still addressable by the id it chose.
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $storage = new AttachmentStorage();
        $storage->requestAttachments()->add(new Attachment(
            '<invoice@example.com>',
            'file',
            'invoice.pdf',
            'application/pdf',
            MemoryStream::create()->write('%PDF-1.7 invoice bytes')->rewind(),
        ));

        $document = $fixture->envelope(
            body: '<message><xop:Include xmlns:xop="'.self::XOP.'" href="cid:invoice@example.com"/></message>',
        );

        // The Body itself cannot be encrypted while it carries a pointer, which is the standing refusal, so
        // this is the MTOM shape: encrypt the attachment, and let the wrapped key's bytes travel in a part.
        $carriers = AttachmentParts::request($storage, ExternalPartCoverage::Content);
        (new Encryption(new GeneratedSessionKey($fixture->leafCertificate, optimizedCipherBytes: $carriers)))
            ->withParts([])
            ->withAttachments(AttachmentParts::request($storage, ExternalPartCoverage::Content))
            ->withOptimizedCipherBytes($carriers)(
                new WsseContext($document, SoapVersion::Soap12, $this->profile(), new ExchangeKeys()),
            );

        // The encoder's own attachment: still there, still under its id, now sealed as ciphertext.
        $sealed = $storage->requestAttachments()->findById('<invoice@example.com>');
        static::assertNotSame('%PDF-1.7 invoice bytes', $sealed->content->rewind()->getContents());

        // Its pointer in the Body is untouched, so the encoder's reference still addresses it.
        static::assertStringContainsString('href="cid:invoice@example.com"', $document->toXmlString());

        // One minted part for the wrapped key. The attachment's own ciphertext travels in its own part under
        // a CipherReference, so nothing optimizes it a second time.
        static::assertCount(2, $storage->requestAttachments());
        static::assertCount(1, $this->pointersInside($document, 'CipherValue'));
    }

    public function test_signing_after_it_is_refused_rather_than_silently_disabled(): void
    {
        // WSS4J turns the option off when encryption comes before signing, warning that the cipher bytes will
        // not be signed. We refuse instead: a security-relevant setting that disables itself is worse than an
        // error, because nothing downstream can tell it happened.
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $storage = new AttachmentStorage();
        $document = $this->encrypt($storage, $fixture);

        $this->expectException(SigningFailed::class);
        $this->expectExceptionMessage('points at content the signature does not cover');

        $fixture->sign([WsseSignatureFixture::bodyTarget()], document: $document);
    }

    private function encrypt(
        AttachmentStorageInterface $storage,
        ?WsseSignatureFixture $fixture = null,
    ): Document {
        $fixture ??= WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->envelope(body: '<data>'.self::PLAINTEXT.'</data>');

        // Registered on both the key source and the block: whether a cipher value is optimized is decided per
        // element, so the wrapped key and the content are separate choices over one set of carriers.
        $carriers = AttachmentParts::request($storage, ExternalPartCoverage::Content);

        (new Encryption(new GeneratedSessionKey($fixture->leafCertificate, optimizedCipherBytes: $carriers)))
            ->withOptimizedCipherBytes($carriers)(
                new WsseContext($document, SoapVersion::Soap12, $this->profile(), new ExchangeKeys()),
            );

        return $document;
    }

    /**
     * The pointers sitting inside one kind of element, which is how many values actually got optimized.
     *
     * @return list<string>
     */
    private function pointersInside(Document $document, string $localName): array
    {
        $hrefs = [];
        foreach ($document->toUnsafeDocument()->getElementsByTagNameNS(self::XENC, $localName) as $element) {
            if (!$element instanceof Element) {
                continue;
            }

            foreach ($element->getElementsByTagNameNS(self::XOP, 'Include') as $include) {
                if ($include instanceof Element) {
                    $hrefs[] = $include->getAttribute('href');
                }
            }
        }

        return $hrefs;
    }

    /**
     * @return list<Element>
     */
    private function cipherValues(Document $document): array
    {
        $values = [];
        foreach ($document->toUnsafeDocument()->getElementsByTagNameNS(self::XENC, 'CipherValue') as $element) {
            if ($element instanceof Element) {
                $values[] = $element;
            }
        }

        return $values;
    }

    /**
     * @return list<string>
     */
    private function pointers(Document $document): array
    {
        $hrefs = [];
        foreach ($document->toUnsafeDocument()->getElementsByTagNameNS(self::XOP, 'Include') as $element) {
            if ($element instanceof Element) {
                $hrefs[] = $element->getAttribute('href');
            }
        }

        return $hrefs;
    }

    private function profile(): SecurityProfile
    {
        return new SecurityProfile(
            crypto: new CryptoPolicy(dataEncryptionMethod: DataEncryptionMethod::AES256_GCM),
        );
    }
}
