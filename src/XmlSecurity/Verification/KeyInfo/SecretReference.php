<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo;

use SensitiveParameter;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;

/**
 * A ds:KeyInfo that named a symmetric secret, resolved to the secret itself.
 *
 * Resolved rather than named, unlike the identifier forms of a certificate reference: a secret has no local
 * store to be searched by identifier. The only secret a signature may verify against is one this exchange
 * established, so whoever reads the ds:KeyInfo is also the only thing that can resolve it, and a reference it
 * cannot resolve is a refusal rather than a pointer passed further on.
 *
 * @psalm-immutable
 */
final readonly class SecretReference implements KeyReference
{
    public function __construct(
        #[SensitiveParameter] public SessionKey $secret,
    ) {
    }
}
