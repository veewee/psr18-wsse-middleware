<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Attachment;

use PHPUnit\Framework\TestCase;
use Soap\Psr18AttachmentsMiddleware\Attachment\Attachment;
use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\AttachmentsPackage;

final class AttachmentsPackageTest extends TestCase
{
    public function test_it_accepts_the_installed_package(): void
    {
        $this->expectNotToPerformAssertions();

        AttachmentsPackage::assertSupported();
    }

    /**
     * The guard probes for capability rather than for a version string, so what it actually asserts is that
     * these two named constructors still exist. Pinning them here means a rename in that package surfaces as
     * this test rather than as an undefined method from inside the encryption path.
     */
    public function test_it_probes_the_methods_the_adapter_depends_on(): void
    {
        static::assertTrue(method_exists(Attachment::class, 'fromHeaders'));
        static::assertTrue(method_exists(Attachment::class, 'withHeaders'));
    }
}
