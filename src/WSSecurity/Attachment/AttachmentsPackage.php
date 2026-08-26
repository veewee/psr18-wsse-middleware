<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Attachment;

use Composer\InstalledVersions;
use Soap\Psr18AttachmentsMiddleware\Attachment\Attachment;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\UnsupportedAttachmentsVersion;

/**
 * Whether the installed attachments middleware can do what this adapter needs of it.
 *
 * The package is suggested rather than required, so composer constrains no version and cannot answer this.
 * Asking here means a miss names the package and the version that fixes it, instead of surfacing as an
 * undefined method from somewhere inside the encryption path.
 */
final class AttachmentsPackage
{
    private const string NAME = 'php-soap/psr18-attachments-middleware';

    private const string MINIMUM_VERSION = '0.12.0';

    /**
     * Asked of the capability rather than of a version string. A path repository or a dev branch has no
     * order against a floor, and the interop harness installs exactly that way. The header set an attachment
     * carries is the newest thing this adapter needs, so the named constructors that go with it answer for
     * the rest.
     *
     * @throws UnsupportedAttachmentsVersion
     */
    public static function assertSupported(): void
    {
        if (method_exists(Attachment::class, 'fromHeaders') && method_exists(Attachment::class, 'withHeaders')) {
            return;
        }

        throw UnsupportedAttachmentsVersion::requiresAtLeast(
            self::NAME,
            self::MINIMUM_VERSION,
            InstalledVersions::getPrettyVersion(self::NAME) ?? 'an unknown version',
        );
    }
}
