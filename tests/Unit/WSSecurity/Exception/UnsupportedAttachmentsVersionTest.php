<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Exception;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\UnsupportedAttachmentsVersion;

final class UnsupportedAttachmentsVersionTest extends TestCase
{
    /**
     * The guard this message belongs to cannot be exercised from a test: it fires when the attachments
     * package is too old to carry a re-represented attachment, and the installed one never is. So pin the
     * diagnostic instead, because naming the package, the floor and what is actually installed is the whole
     * reason the check exists rather than letting an undefined method surface from inside encryption.
     */
    public function test_it_names_the_package_the_floor_and_the_installed_version(): void
    {
        $exception = UnsupportedAttachmentsVersion::requiresAtLeast(
            'php-soap/psr18-attachments-middleware',
            '0.11.0',
            '0.9.1',
        );

        static::assertSame(
            'Attachment security needs php-soap/psr18-attachments-middleware 0.11.0 or later to re-represent '
            .'an attachment; 0.9.1 is installed.',
            $exception->getMessage(),
        );
    }
}
