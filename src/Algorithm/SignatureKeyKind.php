<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\Algorithm;

/**
 * The kind of key a signature method is keyed by. An enum rather than a predicate per family, because every
 * consumer has to decide what each kind means: an RSA, DSA or ECDSA method verifies against a certificate,
 * while an HMAC method verifies against a shared secret. Adding a case is therefore a static-analysis error at
 * every decision point instead of silently taking whichever route was the default.
 */
enum SignatureKeyKind
{
    case Rsa;
    case Dsa;
    case Ecdsa;
    case Hmac;
}
