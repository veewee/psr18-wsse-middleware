<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Algorithm;

/**
 * Canonicalization methods. Now a live value: it tells the Canonicalizer whether to canonicalize
 * exclusively and whether to retain comments (the arguments native Dom\Node::C14N takes).
 */
enum SignatureCanonicalization: string
{
    case C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
    case C14N_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';
    case EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    case EXC_C14N_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';

    public function isExclusive(): bool
    {
        return match ($this) {
            self::EXC_C14N, self::EXC_C14N_COMMENTS => true,
            self::C14N, self::C14N_COMMENTS => false,
        };
    }

    public function withComments(): bool
    {
        return match ($this) {
            self::C14N_COMMENTS, self::EXC_C14N_COMMENTS => true,
            self::C14N, self::EXC_C14N => false,
        };
    }

    public static function default(): self
    {
        return self::EXC_C14N;
    }
}
