<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity;

use Phpro\ResourceStream\Factory\MemoryStream;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPart;

final class ExternalPartTest extends TestCase
{
    public function test_it_carries_the_reference_media_type_and_content(): void
    {
        $part = new ExternalPart('cid:invoice@example.com', 'application/pdf', $content = MemoryStream::create());

        static::assertSame('cid:invoice@example.com', $part->reference);
        static::assertSame('application/pdf', $part->mimeType);
        static::assertSame($content, $part->content);
    }

    public function test_a_new_representation_keeps_the_reference(): void
    {
        $part = new ExternalPart('cid:invoice@example.com', 'application/pdf', MemoryStream::create());

        $sealed = $part->withContent($ciphertext = MemoryStream::create(), 'application/octet-stream');

        static::assertNotSame($part, $sealed);
        static::assertSame('cid:invoice@example.com', $sealed->reference);
        static::assertSame('application/octet-stream', $sealed->mimeType);
        static::assertSame($ciphertext, $sealed->content);
    }
}
