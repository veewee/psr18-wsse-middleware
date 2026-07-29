<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\Xml;

use PHPUnit\Framework\TestCase;
use Throwable;
use VeeWee\Xml\Dom\Document;
use VeeWee\Xml\Exception\DoctypeNotAllowedException;
use function VeeWee\Xml\Dom\Configurator\disallow_doctype;

/**
 * Every parse in this library refuses a DOCTYPE, but that refusal is a post-parse check: by the time it runs,
 * libxml has already decided what to do with any entity the DOCTYPE declared. So refusing the document is only
 * half the defence: the other half is that the parse itself never resolves an external entity, which holds
 * because no parse passes any LIBXML_* option. Nothing pinned that, and it is not ours to change: a dependency
 * whose loader started substituting entities would silently turn an already-refused message into a file read
 * or an outbound fetch, and the fetch is the exfiltration channel whether or not the document is then rejected.
 *
 * These tests pin the parse posture the refusal rests on, so losing it fails here rather than in the field.
 */
final class DoctypeDefenceTest extends TestCase
{
    private const CANARY = 'CANARY-EXTERNAL-ENTITY-WAS-RESOLVED';

    private ?string $canaryFile = null;

    protected function tearDown(): void
    {
        if ($this->canaryFile !== null && file_exists($this->canaryFile)) {
            unlink($this->canaryFile);
        }

        $this->canaryFile = null;
    }

    public function test_the_parse_never_resolves_an_external_entity(): void
    {
        // Loaded exactly the way every parse in this library loads, but without the doctype configurator: the
        // refusal would mask what the parse did, and what the parse did is the whole point. Going through the
        // real loader is what makes this a guard: a changed option there is the failure being watched for.
        $root = Document::fromXmlString($this->externalEntityPayload())
            ->toUnsafeDocument()
            ->documentElement;

        static::assertNotNull($root);
        static::assertStringNotContainsString(self::CANARY, $root->textContent);
        // An empty body proves the file was never opened, rather than opened and discarded.
        static::assertSame('', $root->textContent);
    }

    public function test_a_doctype_declaring_an_external_entity_is_refused(): void
    {
        $this->expectException(DoctypeNotAllowedException::class);

        Document::fromXmlString($this->externalEntityPayload(), disallow_doctype());
    }

    public function test_an_entity_expansion_bomb_is_refused_before_it_expands(): void
    {
        // Nine levels of tenfold self-reference: 10^9 expansions if anything expands them. Libxml's own
        // amplification guard refuses it, and the memory bound is what proves nothing expanded: were the
        // guard lost, this would consume gigabytes rather than report a failed assertion.
        $before = memory_get_peak_usage(true);
        $refused = false;

        try {
            Document::fromXmlString($this->entityBomb(), disallow_doctype());
        } catch (Throwable) {
            $refused = true;
        }

        static::assertTrue($refused, 'The entity bomb was accepted.');
        static::assertLessThan(64 * 1024 * 1024, memory_get_peak_usage(true) - $before);
    }

    /**
     * @return non-empty-string
     */
    private function externalEntityPayload(): string
    {
        return '<!DOCTYPE r [<!ENTITY x SYSTEM "file://'.$this->canaryPath().'">]><r>&x;</r>';
    }

    /**
     * @return non-empty-string
     */
    private function entityBomb(): string
    {
        $bomb = '<!DOCTYPE lolz [<!ENTITY lol "lol">';
        for ($level = 1; $level <= 9; $level++) {
            $previous = $level === 1 ? 'lol' : 'lol'.($level - 1);
            $bomb .= '<!ENTITY lol'.$level.' "'.str_repeat('&'.$previous.';', 10).'">';
        }

        return $bomb.']><lolz>&lol9;</lolz>';
    }

    /**
     * A file holding a value that must never appear in any parsed document.
     *
     * @return non-empty-string
     */
    private function canaryPath(): string
    {
        if ($this->canaryFile === null) {
            $file = tempnam(sys_get_temp_dir(), 'wsse-doctype-canary');
            static::assertIsString($file);
            static::assertNotSame('', $file);
            file_put_contents($file, self::CANARY);
            $this->canaryFile = $file;
        }

        return $this->canaryFile;
    }
}
