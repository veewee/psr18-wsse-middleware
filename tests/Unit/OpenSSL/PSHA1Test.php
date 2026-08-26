<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\OpenSSL;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\OpenSSL\PSHA1;

final class PSHA1Test extends TestCase
{
    /**
     * The definition, written out by hand: A(0) is the seed, A(i) is HMAC-SHA1(secret, A(i-1)), and the stream
     * is HMAC-SHA1(secret, A(i) || seed) concatenated. Spelled out step by step rather than looped, so the
     * loop under test is checked against the formula rather than against itself.
     */
    public function test_it_produces_the_stream_the_definition_prescribes(): void
    {
        $bytes = str_repeat("\x2a", 32);
        $secret = SessionKey::fromBytes($bytes);
        $seed = 'WS-SecureConversationWS-SecureConversation'.str_repeat("\x01", 16);

        $a1 = hash_hmac('sha1', $seed, $bytes, true);
        $a2 = hash_hmac('sha1', $a1, $bytes, true);
        $a3 = hash_hmac('sha1', $a2, $bytes, true);
        $expected = hash_hmac('sha1', $a1.$seed, $bytes, true)
            .hash_hmac('sha1', $a2.$seed, $bytes, true)
            .hash_hmac('sha1', $a3.$seed, $bytes, true);

        // Sixty bytes spans three HMAC blocks, so a loop that reused A(i) or restarted it would diverge.
        static::assertSame(
            bin2hex(substr($expected, 0, 60)),
            bin2hex((new PSHA1())->derive($secret, $seed, 0, 60)->bytes()),
        );

        // And the twenty bytes at offset 20 are the second block, not a fresh derivation.
        static::assertSame(
            bin2hex(substr($expected, 20, 20)),
            bin2hex((new PSHA1())->derive($secret, $seed, 20, 20)->bytes()),
        );
    }

    public function test_it_derives_exactly_the_requested_length(): void
    {
        $derive = new PSHA1();
        $secret = SessionKey::fromBytes(str_repeat("\x2a", 32));

        foreach ([1, 16, 20, 32, 48, 64, 128] as $length) {
            static::assertSame($length, strlen($derive->derive($secret, 'seed', 0, $length)->bytes()));
        }
    }

    /**
     * The offset selects a window of one stream, so a key at offset 20 is the twenty bytes that follow the key
     * at offset 0. Two blocks deriving at different offsets therefore get different keys from one secret.
     */
    public function test_the_offset_selects_a_window_of_the_same_stream(): void
    {
        $derive = new PSHA1();
        $secret = SessionKey::fromBytes(str_repeat("\x2a", 32));

        $whole = $derive->derive($secret, 'seed', 0, 40)->bytes();
        $second = $derive->derive($secret, 'seed', 20, 20)->bytes();

        static::assertSame(substr($whole, 20, 20), $second);
        static::assertNotSame(substr($whole, 0, 20), $second);
    }

    public function test_a_different_seed_derives_a_different_key(): void
    {
        $derive = new PSHA1();
        $secret = SessionKey::fromBytes(str_repeat("\x2a", 32));

        static::assertNotSame(
            $derive->derive($secret, 'seed-one', 0, 32)->bytes(),
            $derive->derive($secret, 'seed-two', 0, 32)->bytes(),
        );
    }

    public function test_a_different_secret_derives_a_different_key(): void
    {
        $derive = new PSHA1();

        static::assertNotSame(
            $derive->derive(SessionKey::fromBytes(str_repeat("\x2a", 32)), 'seed', 0, 32)->bytes(),
            $derive->derive(SessionKey::fromBytes(str_repeat("\x2b", 32)), 'seed', 0, 32)->bytes(),
        );
    }

    public function test_an_empty_secret_is_refused_rather_than_derived_from(): void
    {
        $this->expectException(InvalidArgumentException::class);

        (new PSHA1())->derive(SessionKey::fromBytes(''), 'seed', 0, 32);
    }
    public function test_an_offset_below_zero_is_refused_rather_than_silently_shortening_the_key(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('must not be negative');

        (new PSHA1())->derive(SessionKey::fromBytes(str_repeat("\x2a", 32)), 'seed', -10, 32);
    }

    public function test_a_stream_longer_than_the_bound_is_refused_rather_than_generated(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('generates');

        (new PSHA1())->derive(
            SessionKey::fromBytes(str_repeat("\x2a", 32)),
            'seed',
            PSHA1::MAX_GENERATED,
            32,
        );
    }

    public function test_the_bound_counts_the_offset_and_the_length_together(): void
    {
        $derive = new PSHA1();
        $secret = SessionKey::fromBytes(str_repeat("\x2a", 32));

        static::assertSame(
            32,
            strlen($derive->derive($secret, 'seed', PSHA1::MAX_GENERATED - 32, 32)->bytes()),
        );
    }
}
