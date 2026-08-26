<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\OpenSSL;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;

final class DigestTest extends TestCase
{
    public function test_it_hashes_with_the_selected_method_as_raw_bytes(): void
    {
        $digest = new Digest();
        $data = 'the quick brown fox';

        static::assertSame(hash('sha256', $data, true), $digest->hash($data, DigestMethod::SHA256));
        static::assertSame(20, strlen($digest->hash($data, DigestMethod::SHA1)));
        static::assertSame(32, strlen($digest->hash($data, DigestMethod::SHA256)));
        static::assertSame(48, strlen($digest->hash($data, DigestMethod::SHA384)));
        static::assertSame(64, strlen($digest->hash($data, DigestMethod::SHA512)));
        static::assertSame(20, strlen($digest->hash($data, DigestMethod::RIPEMD160)));
    }

    public function test_a_tampered_message_produces_a_different_digest(): void
    {
        $digest = new Digest();

        static::assertNotSame(
            $digest->hash('original', DigestMethod::SHA256),
            $digest->hash('tampered', DigestMethod::SHA256),
        );
    }

    public function test_equals_is_true_for_identical_bytes_and_false_otherwise(): void
    {
        $digest = new Digest();
        $known = $digest->hash('payload', DigestMethod::SHA256);

        static::assertTrue($digest->equals($known, $digest->hash('payload', DigestMethod::SHA256)));
        static::assertFalse($digest->equals($known, $digest->hash('other', DigestMethod::SHA256)));
        static::assertFalse($digest->equals($known, 'short'));
    }
}
