<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Algorithm;

/**
 * Canonicalization methods. A live value: it tells the Canonicalizer whether to retain comments. Only the
 * exclusive variants are represented, since exclusive canonicalization is what WSSE signatures use.
 */
enum SignatureCanonicalization: string
{
    case EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    case EXC_C14N_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';

    public function withComments(): bool
    {
        return $this === self::EXC_C14N_COMMENTS;
    }

    public static function default(): self
    {
        return self::EXC_C14N;
    }
}
