<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\KeyStore\Metadata;

use PHPUnit\Framework\TestCase;
use Psl\DateTime\Timestamp;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\ValidityWindow;

final class ValidityWindowTest extends TestCase
{
    public function test_it_permits_a_moment_inside_the_window(): void
    {
        static::assertTrue($this->window()->permits(Timestamp::fromParts(150)));
    }

    public function test_it_permits_the_boundaries(): void
    {
        $window = $this->window();

        static::assertTrue($window->permits(Timestamp::fromParts(100)));
        static::assertTrue($window->permits(Timestamp::fromParts(200)));
    }

    public function test_it_rejects_a_moment_before_the_window(): void
    {
        static::assertFalse($this->window()->permits(Timestamp::fromParts(99)));
    }

    public function test_it_rejects_a_moment_after_the_window(): void
    {
        static::assertFalse($this->window()->permits(Timestamp::fromParts(201)));
    }

    private function window(): ValidityWindow
    {
        return new ValidityWindow(Timestamp::fromParts(100), Timestamp::fromParts(200));
    }
}
