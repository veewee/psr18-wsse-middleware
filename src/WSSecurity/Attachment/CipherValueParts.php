<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Attachment;

use Phpro\ResourceStream\Factory\MemoryStream;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\CipherValueSink;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalParts;

/**
 * Puts cipher bytes in a MIME part of their own, which is where a peer with storeBytesInAttachment on looks
 * for them.
 *
 * This class is the whole of what the profile decides about that: the media type, which WSS4J defined and
 * every peer matches, and the fact that "somewhere else" means an attachment. The engine hands over octets
 * and is handed back something to point at.
 */
final readonly class CipherValueParts implements CipherValueSink
{
    /**
     * WSS4J's own type for a part holding nothing but cipher bytes. Not registered anywhere, and not read by
     * anything: a peer resolves the pointer and decrypts what it finds. It travels because the peers put it
     * there, and a part with no type at all is one an intermediary may guess about.
     */
    private const MEDIA_TYPE = 'application/ciphervalue';

    /**
     * What the part is, for whoever reads the wire. The adapter storing it cannot know: it sees octets and a
     * media type, and only this class knows they are one element's cipher value. Several parts share the name
     * in a message that optimizes more than one value, which is what the reference is for.
     */
    private const NAME = 'CipherValue';

    public function __construct(
        private ExternalParts $carriers,
    ) {
    }

    public function store(string $bytes): string
    {
        // Held in memory rather than streamed: these are the bytes the cipher just returned, so they are
        // already there, and the part is minted only to carry them out again.
        return $this->carriers
            ->add(MemoryStream::create()->write($bytes)->rewind(), self::MEDIA_TYPE, self::NAME)
            ->reference;
    }
}
