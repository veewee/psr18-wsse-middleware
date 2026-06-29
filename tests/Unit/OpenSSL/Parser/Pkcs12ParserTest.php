<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\OpenSSL\Parser;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\OpenSSL\Parser\Pkcs12Parser;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\Pkcs12Exception;
use SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\KeyStore\Fixture\Pkcs12Fixture;

final class Pkcs12ParserTest extends TestCase
{
    public function test_it_reads_the_leaf_key_and_ca_chain(): void
    {
        $bundle = (new Pkcs12Parser())->parse(Pkcs12Fixture::create('secret')->p12, 'secret');

        static::assertStringContainsString('CN=Test Leaf', $bundle->leaf()->info()->subject()->toString());
        static::assertStringContainsString('PRIVATE KEY', $bundle->privateKey->contents());

        $chain = $bundle->chain->all();
        static::assertCount(2, $chain);
        static::assertStringContainsString('CN=Test CA', $chain[1]->info()->subject()->toString());
    }

    public function test_it_reads_a_bundle_without_an_embedded_ca_chain(): void
    {
        $bundle = (new Pkcs12Parser())->parse(Pkcs12Fixture::create('secret', withCaChain: false)->p12, 'secret');

        static::assertCount(1, $bundle->chain->all());
    }

    public function test_it_rejects_a_wrong_passphrase_without_leaking_it(): void
    {
        try {
            (new Pkcs12Parser())->parse(Pkcs12Fixture::create('secret')->p12, 'wrong-passphrase');
            static::fail('Expected a Pkcs12Exception to be thrown.');
        } catch (Pkcs12Exception $exception) {
            static::assertStringNotContainsString('wrong-passphrase', $exception->getMessage());
        }
    }

    public function test_it_rejects_unreadable_contents(): void
    {
        $this->expectException(Pkcs12Exception::class);
        (new Pkcs12Parser())->parse('not-a-pkcs12-blob', '');
    }
}
