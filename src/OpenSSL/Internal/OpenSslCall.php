<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL\Internal;

use Psl\Ref;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\OpenSslException;

/**
 * Runs an openssl_* call with its warnings boxed: PHP warnings are captured instead of emitted, and the
 * OpenSSL error queue is drained so the real reason is available. Replaces scattered `@` error suppression.
 *
 * @internal
 */
final class OpenSslCall
{
    /**
     * Runs an openssl_* call whose meaningful result is written to a by-reference out-parameter (openssl_sign,
     * openssl_public_encrypt, openssl_private_decrypt, openssl_pkey_export, openssl_x509_export, ...). Supplies
     * the holder, runs the call (which writes the holder and returns the openssl success flag) and returns the
     * captured value, so call sites do not repeat the Ref boilerplate.
     *
     * @param callable(Ref<string>): bool $operation
     *
     * @throws OpenSslException when the operation reports failure
     */
    public static function output(callable $operation, string $description = 'complete the OpenSSL operation'): string
    {
        /** @var Ref<string> $captured */
        $captured = new Ref('');
        self::run(static fn (): bool => $operation($captured), $description);

        return $captured->value;
    }

    /**
     * Runs the call and returns the actual result, with the failure `false` excluded: a `false` result (how
     * the openssl_* functions report failure) becomes an OpenSslException carrying the real reason.
     *
     * @template T
     *
     * @param callable():(T|false) $operation
     * @param string $description human-readable label of what was attempted, for the thrown message
     *
     * @return T
     *
     * @throws OpenSslException when the operation reports failure
     */
    public static function run(callable $operation, string $description = 'complete the OpenSSL operation'): mixed
    {
        [$result, $reason] = self::capture($operation);
        if ($result === false) {
            throw OpenSslException::operationFailed($description, $reason);
        }

        return $result;
    }

    /**
     * Boxes warnings and drains the error queue, returning the raw result (including `false`) and the
     * captured reason. Use when `false` is a meaningful value to interpret rather than a failure (e.g.
     * openssl_x509_checkpurpose's not-trusted result); otherwise prefer run().
     *
     * @template T
     *
     * @param callable():T $operation
     *
     * @return array{0: T, 1: string}
     */
    public static function capture(callable $operation): array
    {
        // Drop any stale queue entries so we only report this call's errors.
        do {
            $stale = openssl_error_string();
        } while ($stale !== false);

        /** @var list<string> $messages */
        $messages = [];
        set_error_handler(static function (int $_severity, string $message) use (&$messages): bool {
            $messages[] = $message;

            return true;
        });

        try {
            $result = $operation();
        } finally {
            restore_error_handler();
        }

        while (($opensslError = openssl_error_string()) !== false) {
            $messages[] = $opensslError;
        }

        return [$result, implode('; ', $messages)];
    }
}
