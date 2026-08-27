<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Keys;

use LogicException;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\ExchangeKeys;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\KeyRequest;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\SymmetricKey;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\SymmetricKeySource;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\EncryptedKeySha1KeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;

final class ExchangeKeysTest extends TestCase
{
    public function test_one_source_mints_once_and_every_later_caller_gets_that_key(): void
    {
        $keys = new ExchangeKeys();
        $source = $this->source();
        $mints = 0;

        $first = $keys->materialize($source, function () use (&$mints): SymmetricKey {
            $mints++;

            return $this->key('first');
        });
        $second = $keys->materialize($source, function () use (&$mints): SymmetricKey {
            $mints++;

            return $this->key('second');
        });

        static::assertSame(1, $mints);
        static::assertSame($first, $second);
    }

    /**
     * Identity is the sharing mechanism: two sources configured identically are two keys, because a caller
     * that wanted one key would have passed one object.
     */
    public function test_two_distinct_sources_mint_two_keys(): void
    {
        $keys = new ExchangeKeys();

        $first = $keys->materialize($this->source(), fn (): SymmetricKey => $this->key('first'));
        $second = $keys->materialize($this->source(), fn (): SymmetricKey => $this->key('second'));

        static::assertNotSame($first, $second);
    }

    public function test_materializing_establishes_every_wire_identifier_the_key_named(): void
    {
        $keys = new ExchangeKeys();
        $key = $this->key('secret', ['sha1-of-the-wrapped-bytes', '#EK-1']);

        $keys->materialize($this->source(), static fn (): SymmetricKey => $key);

        static::assertSame($key->bytes, $keys->resolve('sha1-of-the-wrapped-bytes'));
        static::assertSame($key->bytes, $keys->resolve('#EK-1'));
    }

    public function test_an_identifier_this_exchange_never_established_resolves_to_nothing(): void
    {
        static::assertNull((new ExchangeKeys())->resolve('a-key-from-somewhere-else'));
    }

    public function test_a_secret_can_be_established_without_a_source(): void
    {
        // The pre-shared case: nothing was minted, so nothing materialized, but the secret still has to be
        // resolvable by the reference an inbound message names it with.
        $keys = new ExchangeKeys();
        $secret = SessionKey::fromBytes(str_repeat("\x2a", 32));

        $keys->establish($secret, 'the-agreed-identifier');

        static::assertSame($secret, $keys->resolve('the-agreed-identifier'));
    }

    public function test_establishing_the_same_identifier_twice_is_not_an_error(): void
    {
        // Both inbound blocks may hold one pre-shared source, and each registers before it resolves.
        $keys = new ExchangeKeys();
        $secret = SessionKey::fromBytes(str_repeat("\x2a", 32));

        $keys->establish($secret, 'the-agreed-identifier');
        $keys->establish($secret, 'the-agreed-identifier');

        static::assertSame($secret, $keys->resolve('the-agreed-identifier'));
    }

    public function test_the_same_secret_established_twice_under_one_identifier_stays_that_secret(): void
    {
        // Equal bytes rather than the same instance: two sources configured alike are still one secret.
        $keys = new ExchangeKeys();

        $keys->establish(SessionKey::fromBytes(str_repeat("\x2a", 32)), 'the-agreed-identifier');
        $keys->establish(SessionKey::fromBytes(str_repeat("\x2a", 32)), 'the-agreed-identifier');

        static::assertSame(
            str_repeat("\x2a", 32),
            $keys->resolve('the-agreed-identifier')?->bytes(),
        );
    }

    public function test_a_second_secret_under_an_established_identifier_is_refused(): void
    {
        $keys = new ExchangeKeys();
        $keys->establish(SessionKey::fromBytes(str_repeat("\x2a", 32)), 'the-agreed-identifier');

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('the-agreed-identifier');

        $keys->establish(SessionKey::fromBytes(str_repeat("\x2b", 32)), 'the-agreed-identifier');
    }

    private function source(): SymmetricKeySource
    {
        return new class implements SymmetricKeySource {
            public function resolve(WsseContext $context, KeyRequest $for): SymmetricKey
            {
                // The bag is what is under test; a source is only ever an identity to it.
                throw new LogicException('Not exercised.');
            }
        };
    }

    /**
     * @param list<non-empty-string> $wireIdentifiers
     */
    private function key(string $bytes, array $wireIdentifiers = []): SymmetricKey
    {
        return new SymmetricKey(
            SessionKey::fromBytes($bytes),
            new EncryptedKeySha1KeyIdentifier('base64-sha1'),
            $wireIdentifiers,
        );
    }
}
