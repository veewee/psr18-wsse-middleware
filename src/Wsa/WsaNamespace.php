<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\Wsa;

/**
 * The two WS-Addressing namespace versions, backed by their URI. Defaults to W3C 2005/08.
 */
enum WsaNamespace: string
{
    case W3c200508 = 'http://www.w3.org/2005/08/addressing';
    case Submission200408 = 'http://schemas.xmlsoap.org/ws/2004/08/addressing';

    public function prefix(): string
    {
        return 'wsa';
    }

    public function anonymousUri(): string
    {
        return match ($this) {
            self::W3c200508 => 'http://www.w3.org/2005/08/addressing/anonymous',
            self::Submission200408 => 'http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous',
        };
    }
}
