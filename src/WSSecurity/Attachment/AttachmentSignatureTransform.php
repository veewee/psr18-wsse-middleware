<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Attachment;

use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartCoverage;

/**
 * The transform a ds:Reference declares over an attachment, which is how a coverage is stated on the wire
 * and what a peer checks against the coverage its own policy asked for.
 *
 * Named after the attachment rather than after SwA, like the adapter is: the profile defines these URIs but
 * they serve MTOM identically, since both packagings put the bytes in a MIME part addressed by a cid. The
 * interop suite runs every direction under both and nothing here branches on the packaging.
 *
 * It lives here rather than on ExternalPartCoverage, which would be the obvious home, because that enum is
 * part of the engine's seam and the engine is deliberately ignorant of this profile: nothing under
 * XmlSecurity may name SwA, and a method there returning one of these would be the first to do so. So the
 * coverage stays a plain choice and this maps it to the wire one layer up.
 *
 * @see https://docs.oasis-open.org/wss-m/wss/v1.1.1/os/wss-SwAProfile-v1.1.1-os.html
 */
enum AttachmentSignatureTransform: string
{
    /** Covers an attachment's content and none of its MIME headers. */
    case Content = 'http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform';

    /** Covers an attachment's canonical header block as well as its content. */
    case Complete = 'http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Complete-Signature-Transform';

    public static function for(ExternalPartCoverage $coverage): self
    {
        return match ($coverage) {
            ExternalPartCoverage::Content => self::Content,
            ExternalPartCoverage::Complete => self::Complete,
        };
    }
}
