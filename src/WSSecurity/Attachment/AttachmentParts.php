<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Attachment;

use Composer\InstalledVersions;
use Phpro\ResourceStream\Factory\MemoryStream;
use Phpro\ResourceStream\ResourceStream;
use Soap\Psr18AttachmentsMiddleware\Attachment\Attachment;
use Soap\Psr18AttachmentsMiddleware\Attachment\AttachmentsCollection;
use Soap\Psr18AttachmentsMiddleware\Attachment\Cid;
use Soap\Psr18AttachmentsMiddleware\Storage\AttachmentStorageInterface;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\UnknownAttachment;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\UnsupportedAttachmentsVersion;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPart;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartCoverage;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalParts;

/**
 * The shipped ExternalParts implementation over the attachments middleware's storage, so a caller writes no
 * glue at all.
 *
 * It sits beside Part, and the symmetry is the point: Part names the regions of the document to protect,
 * AttachmentParts names the attachment-backed ones, and the two go to withParts() and withAttachments().
 *
 * Named after what it adapts rather than after SwA, because the mechanism is identical under MTOM: both put
 * the bytes in a MIME part addressed by a cid. This is the only class in this package that names the
 * attachments middleware, and the engine below it never hears the word attachment.
 */
final readonly class AttachmentParts implements ExternalParts
{
    private const PACKAGE = 'php-soap/psr18-attachments-middleware';
    private const MINIMUM_VERSION = '0.12.0';
    private const OPAQUE_MEDIA_TYPE = 'application/octet-stream';

    private function __construct(
        private AttachmentStorageInterface $storage,
        private AttachmentSide $side,
        private ExternalPartCoverage $coverage,
        private MimeHeaderBlock $headerBlock,
    ) {
    }

    public static function request(
        AttachmentStorageInterface $storage,
        ExternalPartCoverage $coverage = ExternalPartCoverage::Content,
    ): self {
        self::assertSupported();

        return new self($storage, AttachmentSide::Request, $coverage, new MimeHeaderBlock());
    }

    public static function response(
        AttachmentStorageInterface $storage,
        ExternalPartCoverage $coverage = ExternalPartCoverage::Content,
    ): self {
        self::assertSupported();

        return new self($storage, AttachmentSide::Response, $coverage, new MimeHeaderBlock());
    }

    public function coverage(): ExternalPartCoverage
    {
        return $this->coverage;
    }

    public function collect(): ExternalPartList
    {
        return $this->collectEach(
            fn (Attachment $attachment, ResourceStream $content): ResourceStream => $this->coverage === ExternalPartCoverage::Complete
                ? MemoryStream::create()
                    ->write($this->headerBlock->canonicalize($attachment->headers).$content->getContents())
                    ->rewind()
                : $content,
        );
    }

    public function collectSealed(): ExternalPartList
    {
        return $this->collectEach(
            static fn (Attachment $attachment, ResourceStream $content): ResourceStream => $content,
        );
    }

    /**
     * @param callable(Attachment, ResourceStream<resource>): ResourceStream<resource> $octets
     */
    private function collectEach(callable $octets): ExternalPartList
    {
        $parts = [];
        foreach ($this->attachments() as $attachment) {
            $parts[] = new ExternalPart(
                reference: Cid::uriFor($attachment->id),
                mimeType: $this->declaredMediaType($attachment),
                // Rewound because a message may be collected twice: sign-then-encrypt digests the plaintext
                // and then seals the same plaintext, and a stream is single-use.
                content: $octets($attachment, $attachment->content->rewind()),
            );
        }

        return ExternalPartList::of(...$parts);
    }

    public function replace(ExternalPartList $parts): void
    {
        foreach ($parts as $part) {
            $attachment = $this->attachments()->find(
                static fn (Attachment $attachment): bool => Cid::uriFor($attachment->id) === $part->reference,
            ) ?? throw UnknownAttachment::forReference($part->reference);

            $this->attachments()->replace(
                $this->coverage === ExternalPartCoverage::Complete
                    ? $this->restored($attachment, $part)
                    : $this->reclothed($attachment, $part)
            );
        }
    }

    /**
     * A part whose metadata was covered carries its header set inside its own octets, so the bytes after the
     * blank line are the file and the headers before it are what it travelled as.
     *
     * A set naming another attachment is refused by the attachment itself. The Content-ID is how a reference
     * bound this part to what was covered, so letting the octets rewrite it would undo that binding.
     */
    private function restored(Attachment $attachment, ExternalPart $part): Attachment
    {
        $decoded = $this->headerBlock->decode($part->content->rewind()->getContents());

        return $attachment
            ->withContent(MemoryStream::create()->write($decoded->content)->rewind(), self::OPAQUE_MEDIA_TYPE)
            ->withHeaders($decoded->headers);
    }

    /**
     * The media type is written back as a header rather than as the scalar, so one carrying a charset comes
     * back whole. A part covered completely by a signature and encrypted content-only is verified against
     * those headers, and an essence string would not reproduce them.
     */
    private function reclothed(Attachment $attachment, ExternalPart $part): Attachment
    {
        return $attachment
            ->withContent($part->content, $part->mimeType)
            ->withHeaders($attachment->headers->replace('Content-Type', $part->mimeType));
    }

    /**
     * The whole Content-Type header rather than its essence, since that is what a peer restoring this part
     * has to be handed back. The attachments package leaves the media type free-form and defaults it to the
     * opaque type when it cannot name one, so an absent or empty one matches that rather than emitting an
     * empty MimeType attribute.
     *
     * @return non-empty-string
     */
    private function declaredMediaType(Attachment $attachment): string
    {
        $declared = $attachment->headers->get('Content-Type') ?? $attachment->mimeType;

        return '' === $declared ? self::OPAQUE_MEDIA_TYPE : $declared;
    }

    /**
     * Resolved per call, never captured: AttachmentsMiddleware swaps both collection instances on every
     * request, so an adapter holding one would be stale from the second call onward.
     */
    private function attachments(): AttachmentsCollection
    {
        return $this->side === AttachmentSide::Request
            ? $this->storage->requestAttachments()
            : $this->storage->responseAttachments();
    }

    /**
     * The header set an attachment carries is the newest thing this adapter needs from that package, so the
     * named constructors that go with it answer for the rest. A version string cannot be the gate: a path
     * repository or a dev branch has no order against a floor, and the interop harness installs exactly that
     * way.
     */
    private static function assertSupported(): void
    {
        if (method_exists(Attachment::class, 'fromHeaders') && method_exists(Attachment::class, 'withHeaders')) {
            return;
        }

        throw UnsupportedAttachmentsVersion::requiresAtLeast(
            self::PACKAGE,
            self::MINIMUM_VERSION,
            InstalledVersions::getPrettyVersion(self::PACKAGE) ?? 'an unknown version',
        );
    }
}
