<?php declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyStore;

interface KeyInterface
{
    /**
     * The RAW content of the key.
     */
    public function contents(): string;
}
