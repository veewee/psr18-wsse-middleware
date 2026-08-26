<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\Wsa;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Wsa\MessageId;

final class MessageIdTest extends TestCase
{
    public function test_it_generates_a_uuid_v4_prefixed_message_id(): void
    {
        $id = MessageId::generate()->value();

        static::assertMatchesRegularExpression(
            '/^uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i',
            $id
        );
    }

    public function test_each_generated_id_is_unique(): void
    {
        static::assertNotSame(MessageId::generate()->value(), MessageId::generate()->value());
    }
}
