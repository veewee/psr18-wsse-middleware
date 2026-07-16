<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Signing;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\DigestResult;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\SignedInfoBuilder;
use VeeWee\Xml\Dom\Document;

final class SignedInfoBuilderTest extends TestCase
{
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';
    private const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';

    public function test_it_emits_the_signed_info_structure(): void
    {
        $signedInfo = $this->build([
            new DigestResult('Body-1', 'AAA=', DigestMethod::SHA256),
            new DigestResult('Ts-1', 'BBB=', DigestMethod::SHA256),
        ]);

        static::assertSame('SignedInfo', $signedInfo->localName);
        static::assertSame(self::DS, $signedInfo->namespaceURI);
        static::assertSame('CanonicalizationMethod', $this->childAt($signedInfo, 0)->localName);
        static::assertSame('SignatureMethod', $this->childAt($signedInfo, 1)->localName);
        static::assertCount(2, $this->childrenByLocalName($signedInfo, 'Reference'));
    }

    public function test_the_reference_uri_carries_a_hash_prefix(): void
    {
        $signedInfo = $this->build([new DigestResult('Body-1', 'AAA=', DigestMethod::SHA256)]);

        $reference = $this->childrenByLocalName($signedInfo, 'Reference')[0];
        static::assertSame('#Body-1', $reference->getAttribute('URI'));
    }

    public function test_the_algorithm_attributes_match_the_enum_values(): void
    {
        $signedInfo = $this->build([new DigestResult('Body-1', 'AAA=', DigestMethod::SHA256)]);

        static::assertSame(
            SignatureCanonicalization::EXC_C14N->value,
            $this->childAt($signedInfo, 0)->getAttribute('Algorithm'),
        );
        static::assertSame(
            SignatureMethod::RSA_SHA256->value,
            $this->childAt($signedInfo, 1)->getAttribute('Algorithm'),
        );
    }

    public function test_each_reference_emits_a_digest_method_and_value(): void
    {
        $signedInfo = $this->build([new DigestResult('Body-1', 'AAA=', DigestMethod::SHA256)]);

        $reference = $this->childrenByLocalName($signedInfo, 'Reference')[0];
        $digestMethod = $this->childrenByLocalName($reference, 'DigestMethod')[0];
        $digestValue = $this->childrenByLocalName($reference, 'DigestValue')[0];

        static::assertSame(DigestMethod::SHA256->value, $digestMethod->getAttribute('Algorithm'));
        static::assertSame('AAA=', $digestValue->textContent);
    }

    public function test_each_reference_declares_the_exclusive_c14n_transform(): void
    {
        $signedInfo = $this->build([new DigestResult('Body-1', 'AAA=', DigestMethod::SHA256)]);

        $reference = $this->childrenByLocalName($signedInfo, 'Reference')[0];
        $transforms = $this->childrenByLocalName($reference, 'Transforms')[0];
        $transform = $this->childrenByLocalName($transforms, 'Transform')[0];

        static::assertSame(self::EXC_C14N, $transform->getAttribute('Algorithm'));
    }

    public function test_the_reference_transform_matches_the_chosen_canonicalization(): void
    {
        $signedInfo = $this->build(
            [new DigestResult('Body-1', 'AAA=', DigestMethod::SHA256)],
            SignatureCanonicalization::C14N,
        );

        static::assertSame(
            SignatureCanonicalization::C14N->value,
            $this->childAt($signedInfo, 0)->getAttribute('Algorithm'),
        );

        $reference = $this->childrenByLocalName($signedInfo, 'Reference')[0];
        $transforms = $this->childrenByLocalName($reference, 'Transforms')[0];
        $transform = $this->childrenByLocalName($transforms, 'Transform')[0];
        static::assertSame(SignatureCanonicalization::C14N->value, $transform->getAttribute('Algorithm'));
    }

    /**
     * @param non-empty-list<DigestResult> $results
     */
    private function build(
        array $results,
        SignatureCanonicalization $canonicalization = SignatureCanonicalization::EXC_C14N,
    ): Element {
        return (new SignedInfoBuilder())->build(
            Document::fromXmlString('<root/>'),
            $canonicalization,
            SignatureMethod::RSA_SHA256,
            $results,
        );
    }

    private function childAt(Element $element, int $index): Element
    {
        $elements = [];
        foreach ($element->childNodes as $child) {
            if ($child instanceof Element) {
                $elements[] = $child;
            }
        }

        return $elements[$index];
    }

    /**
     * @param non-empty-string $localName
     *
     * @return list<Element>
     */
    private function childrenByLocalName(Element $element, string $localName): array
    {
        $matches = [];
        foreach ($element->childNodes as $child) {
            if ($child instanceof Element && $child->localName === $localName) {
                $matches[] = $child;
            }
        }

        return $matches;
    }
}
