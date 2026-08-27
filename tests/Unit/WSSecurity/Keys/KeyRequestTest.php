<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Keys;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\KeyRequest;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\SymmetricKey;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\EncryptedKeySha1KeyIdentifier;

final class KeyRequestTest extends TestCase
{
    public function test_a_request_with_no_length_preference_enforces_nothing(): void
    {
        KeyRequest::any()->enforce($this->key(32), 'The key', 'unreachable');

        static::assertFalse(KeyRequest::any()->mandatory);
    }

    public function test_a_preferred_length_is_not_enforced(): void
    {
        KeyRequest::preferably(16)->enforce($this->key(32), 'The key', 'unreachable');

        static::assertFalse(KeyRequest::preferably(16)->mandatory);
    }

    public function test_an_exact_length_that_matches_passes(): void
    {
        KeyRequest::exactly(32)->enforce($this->key(32), 'The key', 'unreachable');

        static::assertTrue(KeyRequest::exactly(32)->mandatory);
    }

    public function test_an_exact_length_that_differs_names_both_widths_and_the_remedy(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The secret is 16 bytes and this block needs exactly 32. Do the thing.');

        KeyRequest::exactly(32)->enforce($this->key(16), 'The secret', 'Do the thing.');
    }

    private function key(int $length): SymmetricKey
    {
        return new SymmetricKey(
            SessionKey::fromBytes(str_repeat("\x2a", $length)),
            new EncryptedKeySha1KeyIdentifier('an-identifier'),
            ['an-identifier'],
        );
    }
}
