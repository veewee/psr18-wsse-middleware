<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound;

use Dom\Element;
use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use Soap\Psr18AttachmentsMiddleware\Storage\AttachmentStorage;
use Soap\Psr18AttachmentsMiddleware\Storage\AttachmentStorageInterface;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\AttachmentParts;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\Decrypt;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\ResolveOptimizedBytes;
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
        ))(new WsseContext($document, SoapVersion::Soap12, $this->profile()));

        (new Decrypt($fixture->leafKey))(
            new WsseContext($document, SoapVersion::Soap12, $this->profile()),
        );

        static::assertStringContainsString(self::PLAINTEXT, $document->toXmlString());
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

        (new Encryption($fixture->leafCertificate))
            ->withOptimizedCipherBytes(AttachmentParts::request($storage, ExternalPartCoverage::Content))(
                new WsseContext($document, SoapVersion::Soap12, $this->profile()),
            );

        return $document;
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
