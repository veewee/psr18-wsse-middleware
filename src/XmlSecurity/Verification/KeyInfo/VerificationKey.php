<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo;

use SensitiveParameter;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\KeyStore\TrustedSigner;

/**
 * The key a signature will be checked against, once its ds:KeyInfo has been resolved and the resolution has
 * been held against the signature method.
 *
 * The signer travels with it because the two answers are one decision: a certificate has an established
 * identity and a secret has none, so a null signer and a symmetric key are the same fact rather than two
 * fields that could disagree.
 *
 * @psalm-immutable
 */
final readonly class VerificationKey
{
    private function __construct(
        public ?TrustedSigner $signer,
        #[SensitiveParameter] public Certificate|SessionKey $key,
    ) {
    }

    public static function ofSigner(TrustedSigner $signer): self
    {
        return new self($signer, $signer->certificate());
    }

    public static function ofSecret(#[SensitiveParameter] SessionKey $secret): self
    {
        return new self(null, $secret);
    }
}
