<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\Xml\Exception;

use RuntimeException;

final class IdReferenceException extends RuntimeException
{
    public static function notFound(string $id): self
    {
        return new self('No element found for wsu:Id "'.$id.'".');
    }

    public static function ambiguous(string $id): self
    {
        return new self('Multiple elements share the wsu:Id "'.$id.'"; the reference is ambiguous.');
    }
}
