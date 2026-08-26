<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Seam;

use Phpro\ResourceStream\Factory\MemoryStream;
use Phpro\ResourceStream\ResourceStream;
use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\Decrypt;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\ExchangeKeys;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\WrappedSessionKey;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Encryption;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\EncryptionFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPart;
use SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\WsseSignatureFixture;

/**
 * The ExternalParts seam is public, and docs/attachments.md tells a caller to implement it when the bytes live
 * somewhere other than the attachments middleware. This is that caller.
 *
 * ArrayParts is written from the documented contract alone: it holds a plain array, names no foreign package,
 * and does nothing AttachmentParts does. If this stops compiling or stops round-tripping, the published seam
 * changed under everyone who implemented it, which is the whole reason it is worth a test.
 */
#[RequiresPhp('>= 8.4.21')]
final class ThirdPartyExternalPartsTest extends TestCase
{
    private const CID = 'cid:invoice@example.com';
    private const BYTES = '%PDF-1.7 invoice bytes';

    public function test_a_hand_written_adapter_round_trips_without_the_attachments_package(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $parts = new ArrayParts([new ExternalPart(self::CID, 'application/pdf', $this->stream(self::BYTES))]);
        $document = $fixture->envelope();

        (new Encryption(new WrappedSessionKey($fixture->leafCertificate)))
            ->withAttachments($parts)(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile(), new ExchangeKeys()));

        static::assertNotSame(self::BYTES, $parts->only()->content->rewind()->getContents());

        (new Decrypt($fixture->leafKey))
            ->withAttachments($parts)(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile(), new ExchangeKeys()));

        static::assertSame(self::BYTES, $parts->only()->content->rewind()->getContents());
        static::assertSame('application/pdf', $parts->only()->mimeType);
    }

    public function test_a_hand_written_adapter_can_carry_the_cipher_bytes_too(): void
    {
        // The emission half of the same seam. An adapter holding a plain array can mint the part the cipher
        // bytes travel in, which is why minting belongs on the one interface rather than on a second one only
        // the shipped adapter implements.
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $parts = new ArrayParts([]);
        $document = $fixture->envelope();

        (new Encryption(new WrappedSessionKey($fixture->leafCertificate, optimizedCipherBytes: $parts)))
            ->withOptimizedCipherBytes($parts)(
                new WsseContext($document, SoapVersion::Soap12, new SecurityProfile(), new ExchangeKeys()),
            );

        // The wrapped key and the body cipher value, each pointing at a part this adapter minted.
        $minted = $parts->collect();
        static::assertCount(2, $minted);
        foreach ($minted as $part) {
            static::assertSame('application/ciphervalue', $part->mimeType);
            static::assertStringContainsString('href="'.$part->reference.'"', $document->toXmlString());
        }
    }

    public function test_a_spent_stream_is_recovered_because_the_engine_rewinds_before_reading(): void
    {
        // Defence in depth, pinned so it stays. The seam asks an adapter to rewind, and the engine rewinds
        // again at every site that reads a part, so an adapter that forgets seals the real bytes rather than
        // an empty file that would pass every structural check on the far side.
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $spent = $this->stream(self::BYTES);
        $spent->getContents();

        $parts = new ArrayParts([new ExternalPart(self::CID, 'application/pdf', $spent)], rewinds: false);
        $document = $fixture->envelope();

        (new Encryption(new WrappedSessionKey($fixture->leafCertificate)))
            ->withAttachments($parts)(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile(), new ExchangeKeys()));

        (new Decrypt($fixture->leafKey))
            ->withAttachments($parts)(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile(), new ExchangeKeys()));

        static::assertSame(self::BYTES, $parts->only()->content->rewind()->getContents());
    }

    public function test_a_part_that_genuinely_reads_empty_is_refused(): void
    {
        // What the zero-byte guard is actually for: a part with nothing in it. Sealing it would produce a
        // ciphertext that decrypts to nothing and still satisfies every structural check.
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $parts = new ArrayParts([new ExternalPart(self::CID, 'application/pdf', MemoryStream::create())]);

        $this->expectException(EncryptionFailed::class);
        $this->expectExceptionMessage('An external part read zero bytes.');

        (new Encryption(new WrappedSessionKey($fixture->leafCertificate)))
            ->withAttachments($parts)(
                new WsseContext($fixture->envelope(), SoapVersion::Soap12, new SecurityProfile(), new ExchangeKeys()),
            );
    }

    /**
     * @return ResourceStream<resource>
     */
    private function stream(string $contents): ResourceStream
    {
        return MemoryStream::create()->write($contents)->rewind();
    }
}
