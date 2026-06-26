<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\Wsa;

use Symfony\Component\Uid\Uuid;

/**
 * A WS-Addressing message identifier: the globally-unique id a receiver echoes back in wsa:RelatesTo to
 * correlate its reply with this request. A v4 UUID keeps the value unique without any central coordination,
 * and the `uuid:` URI prefix makes it a valid WS-Addressing IRI.
 */
final readonly class MessageId
{
    private function __construct(
        private string $value,
    ) {
    }

    public static function generate(): self
    {
        return new self('uuid:'.Uuid::v4()->toRfc4122());
    }

    public function value(): string
    {
        return $this->value;
    }
}
