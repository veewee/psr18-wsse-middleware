<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml;

use Soap\Psr18WsseMiddleware\Xml\QualifiesNames;
use Soap\Psr18WsseMiddleware\Xml\XmlNamespace;

/**
 * The two dialects of WS-SecureConversation a wsc:DerivedKeyToken may be written in: the 2005/02 draft that
 * shipped in early stacks, and the 200512 OASIS revision that superseded it and is what a modern peer expects.
 *
 * One enum rather than a namespace and an algorithm enum side by side: a dialect is one choice, its derivation
 * algorithm URI is that namespace plus a fixed suffix, and stating the pair twice would be two places for it to
 * drift.
 *
 * This governs what is emitted. Both are accepted on the way in, because which one a peer writes is not
 * something a client gets to constrain.
 */
enum WsSecureConversationVersion: string implements XmlNamespace
{
    use QualifiesNames;

    case V2005_02 = 'http://schemas.xmlsoap.org/ws/2005/02/sc';
    case V2005_12 = 'http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512';

    public function uri(): string
    {
        return $this->value;
    }

    public function prefix(): string
    {
        // One prefix for both, because a message carries one dialect: nothing has to distinguish them by prefix.
        return 'wsc';
    }

    /**
     * The @Algorithm a wsc:DerivedKeyToken in this dialect declares. Each dialect qualifies the same function
     * under its own namespace, so the URI is the namespace plus the function's path.
     *
     * @return non-empty-string
     */
    public function derivationAlgorithm(): string
    {
        return $this->value.'/dk/p_sha1';
    }

    /**
     * The @ValueType a reference to a wsc:DerivedKeyToken in this dialect declares, so a receiver classifying
     * references by their declared type can place it.
     *
     * @return non-empty-string
     */
    public function derivedKeyTokenType(): string
    {
        return $this->value.'/dk';
    }

    public static function default(): self
    {
        return self::V2005_12;
    }
}
