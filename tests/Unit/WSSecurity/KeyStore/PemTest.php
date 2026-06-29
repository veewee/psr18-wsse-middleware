<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\KeyStore;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Pem;

final class PemTest extends TestCase
{
    public function test_it_concatenates_certificates_into_one_bundle(): void
    {
        $pem = Pem::fromCertificates(new Certificate('first-pem'), new Certificate('second-pem'));

        static::assertStringContainsString('first-pem', $pem->toString());
        static::assertStringContainsString('second-pem', $pem->toString());
    }

    public function test_it_writes_itself_to_a_readable_temp_file(): void
    {
        $resource = Pem::fromCertificates(new Certificate('cert-bytes'))->toResource();

        static::assertSame('cert-bytes', (string) file_get_contents((string) $resource->uri()));
    }
}
