<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Seam;

use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPart;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartCoverage;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalParts;

/**
 * An ExternalParts implementation written from docs/attachments.md and nothing else, over a plain array.
 */
final class ArrayParts implements ExternalParts
{
    /**
     * @param list<ExternalPart> $parts
     */
    public function __construct(
        private array $parts,
        private readonly bool $rewinds = true,
    ) {
    }

    public function coverage(): ExternalPartCoverage
    {
        return ExternalPartCoverage::Content;
    }

    public function collect(): ExternalPartList
    {
        $collected = [];
        foreach ($this->parts as $part) {
            $collected[] = $this->rewinds
                ? new ExternalPart($part->reference, $part->mimeType, $part->content->rewind())
                : $part;
        }

        return ExternalPartList::of(...$collected);
    }

    public function replace(ExternalPartList $parts): void
    {
        foreach ($parts as $replacement) {
            foreach ($this->parts as $index => $part) {
                if ($part->reference === $replacement->reference) {
                    $this->parts[$index] = $replacement;
                }
            }
        }
    }

    public function only(): ExternalPart
    {
        return $this->parts[0];
    }
}
