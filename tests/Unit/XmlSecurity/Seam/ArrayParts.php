<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Seam;

use Phpro\ResourceStream\ResourceStream;
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

    public function collectSealed(): ExternalPartList
    {
        return $this->collect();
    }

    /**
     * @param ResourceStream<resource> $content
     * @param non-empty-string         $mimeType
     */
    public function add(ResourceStream $content, string $mimeType, string $name): ExternalPart
    {
        // Any reference this adapter has not handed out already. The seam leaves the form entirely to the
        // implementation, so an array-backed one needs nothing that looks like a Content-ID.
        $part = new ExternalPart('cid:minted-'.count($this->parts).'@arrayparts.test', $mimeType, $content);
        $this->parts[] = $part;

        return $part;
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
