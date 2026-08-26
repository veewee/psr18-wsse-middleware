<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\Xml\Exception;

use RuntimeException;

final class IdReferenceException extends RuntimeException
{
    private function __construct(string $message, public readonly bool $ambiguous)
    {
        parent::__construct($message);
    }

    public static function notFound(string $id): self
    {
        return new self('No element found for id "'.$id.'".', ambiguous: false);
    }

    public static function ambiguous(string $id): self
    {
        return new self('Multiple elements share the id "'.$id.'"; the reference is ambiguous.', ambiguous: true);
    }
}
