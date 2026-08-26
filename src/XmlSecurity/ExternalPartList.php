<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

use Countable;
use InvalidArgumentException;
use IteratorAggregate;
use Traversable;

/**
 * The external parts of one message, in which no two parts share a reference.
 *
 * The uniqueness rule is the reason this is a type rather than an array. A reference addresses exactly one
 * part in both directions: outbound, two parts sharing one would be encrypted twice under a URI that can only
 * name one of them, and inbound, resolving the reference an element declares would be a choice rather than a
 * lookup.
 *
 * @template-implements IteratorAggregate<int, ExternalPart>
 */
final readonly class ExternalPartList implements Countable, IteratorAggregate
{
    /**
     * @param list<ExternalPart> $parts
     */
    private function __construct(
        private array $parts,
    ) {
    }

    /**
     * @no-named-arguments
     *
     * @throws InvalidArgumentException when two parts share a reference
     */
    public static function of(ExternalPart ...$parts): self
    {
        $seen = [];
        foreach ($parts as $part) {
            if (isset($seen[$part->reference])) {
                throw new InvalidArgumentException(sprintf(
                    'Two external parts share the reference "%s"; each reference addresses one part.',
                    $part->reference,
                ));
            }

            $seen[$part->reference] = true;
        }

        return new self($parts);
    }

    public function byReference(string $reference): ?ExternalPart
    {
        foreach ($this->parts as $part) {
            if ($part->reference === $reference) {
                return $part;
            }
        }

        return null;
    }

    public function count(): int
    {
        return count($this->parts);
    }

    public function getIterator(): Traversable
    {
        yield from $this->parts;
    }
}
