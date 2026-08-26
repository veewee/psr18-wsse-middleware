<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\Algorithm;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\Exception\UnsupportedAlgorithmException;
use Soap\Psr18WsseMiddleware\Algorithm\OaepHash;

final class OaepHashTest extends TestCase
{
    public function test_it_maps_an_mgf_uri_back_onto_the_hash(): void
    {
        static::assertSame(OaepHash::Sha1, OaepHash::fromMgfUri(OaepHash::Sha1->mgfUri()));
        static::assertSame(OaepHash::Sha256, OaepHash::fromMgfUri(OaepHash::Sha256->mgfUri()));
    }

    public function test_an_absent_mgf_uri_defaults_to_sha1(): void
    {
        // The XML-Enc spec default when no xenc11:MGF child is declared.
        static::assertSame(OaepHash::Sha1, OaepHash::fromMgfUri(null));
        static::assertSame(OaepHash::Sha1, OaepHash::fromMgfUri(''));
    }

    public function test_it_rejects_an_unknown_mgf_uri(): void
    {
        $this->expectException(UnsupportedAlgorithmException::class);

        OaepHash::fromMgfUri('http://www.w3.org/2009/xmlenc11#mgf1sha512');
    }
}
