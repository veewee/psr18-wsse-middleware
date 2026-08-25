<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity;

use InvalidArgumentException;
use Phpro\ResourceStream\Factory\MemoryStream;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPart;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;

final class ExternalPartListTest extends TestCase
{
    public function test_it_holds_the_parts_in_the_order_given(): void
    {
        $list = ExternalPartList::of(
            $first = $this->part('cid:a@example.com'),
            $second = $this->part('cid:b@example.com'),
        );

        static::assertCount(2, $list);
        static::assertSame([$first, $second], [...$list]);
    }

    public function test_it_can_be_empty(): void
    {
        $list = ExternalPartList::of();

        static::assertCount(0, $list);
        static::assertSame([], [...$list]);
    }

    public function test_it_resolves_a_part_by_its_reference(): void
    {
        $list = ExternalPartList::of(
            $this->part('cid:a@example.com'),
            $second = $this->part('cid:b@example.com'),
        );

        static::assertSame($second, $list->byReference('cid:b@example.com'));
    }

    public function test_it_has_no_part_for_an_unknown_reference(): void
    {
        $list = ExternalPartList::of($this->part('cid:a@example.com'));

        static::assertNull($list->byReference('cid:b@example.com'));
    }

    public function test_it_refuses_two_parts_sharing_a_reference(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Two external parts share the reference "cid:a@example.com"; each reference addresses one part.'
        );

        ExternalPartList::of(
            $this->part('cid:a@example.com'),
            $this->part('cid:a@example.com'),
        );
    }

    private function part(string $reference): ExternalPart
    {
        return new ExternalPart($reference, 'application/pdf', MemoryStream::create());
    }
}
