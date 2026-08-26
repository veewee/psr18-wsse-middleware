<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Attachment;

use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartCoverage;

/**
 * The type an xenc:EncryptedData declares over an attachment, saying whether the part's MIME headers were
 * encrypted alongside its content or left readable beside it.
 *
 * Separate from the signature transform rather than sharing an enum with it, because they are not
 * interchangeable: one is checked against a policy and the other is not, and a single enum would let either
 * be handed to the wrong operation.
 *
 * @see https://docs.oasis-open.org/wss-m/wss/v1.1.1/os/wss-SwAProfile-v1.1.1-os.html
 */
enum AttachmentEncryptedDataType: string
{
    /** The part's content is encrypted while its MIME headers stay readable. */
    case ContentOnly = 'http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Only';

    /** The part's MIME headers are encrypted alongside its content and travel inside the ciphertext. */
    case Complete = 'http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Complete';

    /**
     * The transform a xenc:CipherReference declares, telling a receiver the part it points at holds
     * ciphertext rather than the original bytes.
     *
     * A constant rather than a case, because it is not a choice: there is one, every reference carries it,
     * and it is emitted alongside one of these types rather than instead of one.
     */
    public const string CIPHERTEXT_TRANSFORM = 'http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Ciphertext-Transform';

    public static function for(ExternalPartCoverage $coverage): self
    {
        return match ($coverage) {
            ExternalPartCoverage::Content => self::ContentOnly,
            ExternalPartCoverage::Complete => self::Complete,
        };
    }
}
