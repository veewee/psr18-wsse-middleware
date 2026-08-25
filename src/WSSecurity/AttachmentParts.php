<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity;

use Composer\InstalledVersions;
use Soap\Psr18AttachmentsMiddleware\Attachment\Attachment;
use Soap\Psr18AttachmentsMiddleware\Attachment\AttachmentsCollection;
use Soap\Psr18AttachmentsMiddleware\Attachment\Cid;
use Soap\Psr18AttachmentsMiddleware\Storage\AttachmentStorageInterface;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\UnknownAttachment;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\UnsupportedAttachmentsVersion;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPart;
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
    private const MINIMUM_VERSION = '0.11.0';
    private const OPAQUE_MEDIA_TYPE = 'application/octet-stream';

    private function __construct(
        private AttachmentStorageInterface $storage,
        private AttachmentSide $side,
    ) {
    }

    public static function request(AttachmentStorageInterface $storage): self
    {
        self::assertSupported();

        return new self($storage, AttachmentSide::Request);
    }

    public static function response(AttachmentStorageInterface $storage): self
    {
        self::assertSupported();

        return new self($storage, AttachmentSide::Response);
    }

    public function collect(): ExternalPartList
    {
        $parts = [];
        foreach ($this->attachments() as $attachment) {
            $parts[] = new ExternalPart(
                reference: Cid::uriFor($attachment->id),
                // The attachments package leaves this free-form and defaults it to the opaque type when it
                // cannot name one. Match that rather than emitting an empty MimeType attribute.
                mimeType: '' === $attachment->mimeType ? self::OPAQUE_MEDIA_TYPE : $attachment->mimeType,
                // Rewound because a message may be collected twice: sign-then-encrypt digests the
                // plaintext and then seals the same plaintext, and a stream is single-use.
                content: $attachment->content->rewind(),
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

            $this->attachments()->replace($attachment->withContent($part->content, $part->mimeType));
        }
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
     * The whole external-part representation landed in one release of that package, so its newest symbol
     * answers for all of it. A version string cannot be the gate: a path repository or a dev branch has no
     * order against a floor, and the interop harness installs exactly that way.
     */
    private static function assertSupported(): void
    {
        if (class_exists(Cid::class)) {
            return;
        }

        throw UnsupportedAttachmentsVersion::requiresAtLeast(
            self::PACKAGE,
            self::MINIMUM_VERSION,
            InstalledVersions::getPrettyVersion(self::PACKAGE) ?? 'an unknown version',
        );
    }
}
