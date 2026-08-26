<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\Algorithm;

/**
 * XML-Enc key-transport algorithms. All cases representable for parity; acceptance is governed by the
 * SecurityProfile allow-list (rsa-1_5 is rejected by default).
 */
enum KeyEncryptionMethod: string
{
    case RSA_1_5 = 'http://www.w3.org/2001/04/xmlenc#rsa-1_5';
    case RSA_OAEP_MGF1P = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';
    case RSA_OAEP = 'http://www.w3.org/2009/xmlenc11#rsa-oaep';

    public static function default(): self
    {
        return self::RSA_OAEP;
    }
}
