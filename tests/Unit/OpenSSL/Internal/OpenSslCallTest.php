<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\OpenSSL\Internal;

use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;
use Psl\Ref;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\OpenSslException;
use Soap\Psr18WsseMiddleware\OpenSSL\Internal\OpenSslCall;

final class OpenSslCallTest extends TestCase
{
    public function test_it_returns_the_result_on_success(): void
    {
        static::assertSame(42, OpenSslCall::run(static fn (): int => 42));
    }

    public function test_it_throws_with_the_real_human_readable_reason_when_the_call_fails(): void
    {
        $signature = '';

        try {
            OpenSslCall::run(static function () use (&$signature): bool {
                return openssl_sign('data', $signature, 'this-is-not-a-key');
            }, 'sign the data');
            static::fail('Expected an OpenSslException.');
        } catch (OpenSslException $exception) {
            static::assertStringContainsString('sign the data', $exception->getMessage());
            static::assertStringContainsString('private key', $exception->getMessage());
        }
    }

    public function test_capture_returns_the_raw_result_without_throwing_on_false(): void
    {
        [$result, $reason] = OpenSslCall::capture(static fn (): bool => false);

        static::assertFalse($result);
        static::assertIsString($reason);
    }

    public function test_output_returns_the_captured_out_parameter(): void
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        static::assertInstanceOf(OpenSSLAsymmetricKey::class, $key);

        $signature = OpenSslCall::output(
            static fn (Ref $out): bool => openssl_sign('data', $out->value, $key, OPENSSL_ALGO_SHA256),
            'sign the data',
        );

        static::assertNotSame('', $signature);
    }

    public function test_output_throws_when_the_operation_fails(): void
    {
        $this->expectException(OpenSslException::class);

        OpenSslCall::output(
            static fn (Ref $out): bool => openssl_sign('data', $out->value, 'not-a-key'),
            'sign the data',
        );
    }

    public function test_it_does_not_emit_warnings(): void
    {
        // A warning during a non-failing call must be boxed, not surfaced (PHPUnit would otherwise fail).
        $result = OpenSslCall::run(static function (): string {
            trigger_error('boom', E_USER_WARNING);

            return 'value';
        });

        static::assertSame('value', $result);
    }
}
