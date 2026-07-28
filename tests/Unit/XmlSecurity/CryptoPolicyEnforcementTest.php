<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity;

use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use ReflectionClass;
use ReflectionMethod;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;
use SplFileInfo;

/**
 * An allow-list that nothing reads is worse than no allow-list: it reads as secure-by-default while admitting
 * everything. That is exactly what happened to the key- and data-encryption lists, which were declared,
 * documented and unit-tested on the policy object while no call site ever consulted them.
 *
 * This asserts the invariant structurally rather than trusting a reader to notice: every inbound allow-list
 * CryptoPolicy declares must be consulted somewhere in src/, through either its accepts*() predicate or the
 * accepted*() getter that hands the list to an enforcer. Adding a new allow-list without wiring it up fails
 * here, and so does removing the last consumer of an existing one.
 */
final class CryptoPolicyEnforcementTest extends TestCase
{
    public function test_every_inbound_allow_list_is_consulted_somewhere_in_src(): void
    {
        $sources = $this->sourceFiles();
        $unconsulted = [];

        foreach ($this->allowListDimensions() as $dimension) {
            $predicate = 'accepts' . $dimension;
            $getter = 'accepted' . $dimension . 's';

            if (!$this->isCalledIn($sources, $predicate) && !$this->isCalledIn($sources, $getter)) {
                $unconsulted[] = $predicate . '() / ' . $getter . '()';
            }
        }

        static::assertSame([], $unconsulted, sprintf(
            "These CryptoPolicy allow-lists are declared but never consulted in src/, so they accept "
            . "everything while reading as secure-by-default:\n  %s",
            implode("\n  ", $unconsulted),
        ));
    }

    /**
     * The dimensions are derived from the accepts*() predicates rather than listed here, so a new allow-list
     * is covered the moment it is declared instead of when someone remembers to extend this test.
     *
     * @return non-empty-list<string>
     */
    private function allowListDimensions(): array
    {
        $dimensions = [];
        foreach ((new ReflectionClass(CryptoPolicy::class))->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
            if (str_starts_with($method->getName(), 'accepts')) {
                $dimensions[] = substr($method->getName(), strlen('accepts'));
            }
        }

        static::assertNotEmpty($dimensions, 'CryptoPolicy declares no accepts*() predicates at all.');

        return $dimensions;
    }

    /**
     * @param non-empty-list<string> $sources
     */
    private function isCalledIn(array $sources, string $method): bool
    {
        foreach ($sources as $source) {
            if (str_contains($source, '->' . $method . '(')) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return non-empty-list<string>
     */
    private function sourceFiles(): array
    {
        $root = dirname(__DIR__, 3) . '/src';
        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root));

        $contents = [];
        foreach ($files as $file) {
            if (!$file instanceof SplFileInfo || $file->getExtension() !== 'php') {
                continue;
            }

            // The policy's own accessors do not count as a consumer: F1 and F2 were live while the class
            // itself referenced every list it declared.
            if ($file->getFilename() === 'CryptoPolicy.php') {
                continue;
            }

            $contents[] = (string) file_get_contents($file->getPathname());
        }

        static::assertNotEmpty($contents, 'No source files found to scan.');

        return $contents;
    }
}
