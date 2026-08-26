<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\XmlSecurity\Target;
use Soap\Psr18WsseMiddleware\XmlSecurity\TargetKind;

final class TargetTest extends TestCase
{
    public function test_element_target_carries_the_qualified_name(): void
    {
        $target = Target::element('urn:example', 'Body');

        static::assertSame(TargetKind::Element, $target->kind());
        static::assertSame('urn:example', $target->namespace());
        static::assertSame('Body', $target->localName());
        static::assertNull($target->id());
    }

    public function test_id_target_carries_the_id(): void
    {
        $target = Target::byId('TS-1');

        static::assertSame(TargetKind::Id, $target->kind());
        static::assertSame('TS-1', $target->id());
        static::assertNull($target->namespace());
        static::assertNull($target->localName());
    }

    public function test_targets_are_compared_by_value(): void
    {
        static::assertTrue(Target::element('urn:a', 'X')->equals(Target::element('urn:a', 'X')));
        static::assertFalse(Target::element('urn:a', 'X')->equals(Target::element('urn:a', 'Y')));
        static::assertTrue(Target::byId('a')->equals(Target::byId('a')));
        static::assertFalse(Target::byId('a')->equals(Target::byId('b')));
        static::assertFalse(Target::element('urn:a', 'X')->equals(Target::byId('X')));
    }
}
