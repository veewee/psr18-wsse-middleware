<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Signing;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\SignedInfoBuilder;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\SignedReference;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\SignedTransform;
use VeeWee\Xml\Dom\Document;

final class SignedInfoBuilderTest extends TestCase
{
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';
    private const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    private const SWA_CONTENT = 'http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform';

    public function test_a_reference_can_carry_a_non_fragment_uri_and_its_own_transform(): void
    {
        // An attachment reference breaks both rules the builder used to hard-code: its URI is not '#'.$id,
        // and its transform is not the canonicalization SignedInfo was built with.
        $signedInfo = $this->build([
            new SignedReference(
                'cid:invoice@example.com',
                'AAA=',
                DigestMethod::SHA256,
                [new SignedTransform(self::SWA_CONTENT)],
            ),
        ]);

        $reference = $this->childrenByLocalName($signedInfo, 'Reference')[0];
        static::assertSame('cid:invoice@example.com', $reference->getAttribute('URI'));

        $transform = $this->transformOfFirstReference($signedInfo);
        static::assertSame(self::SWA_CONTENT, $transform->getAttribute('Algorithm'));
        static::assertCount(0, $this->childrenByLocalName($transform, 'InclusiveNamespaces'));
    }

    public function test_it_emits_the_signed_info_structure(): void
    {
        $signedInfo = $this->build([
            new SignedReference('#Body-1', 'AAA=', DigestMethod::SHA256, [new SignedTransform(self::EXC_C14N)]),
            new SignedReference('#Ts-1', 'BBB=', DigestMethod::SHA256, [new SignedTransform(self::EXC_C14N)]),
        ]);

        static::assertSame('SignedInfo', $signedInfo->localName);
        static::assertSame(self::DS, $signedInfo->namespaceURI);
        static::assertSame('CanonicalizationMethod', $this->childAt($signedInfo, 0)->localName);
        static::assertSame('SignatureMethod', $this->childAt($signedInfo, 1)->localName);
        static::assertCount(2, $this->childrenByLocalName($signedInfo, 'Reference'));
    }

    public function test_the_reference_uri_carries_a_hash_prefix(): void
    {
        $signedInfo = $this->build([new SignedReference('#Body-1', 'AAA=', DigestMethod::SHA256, [new SignedTransform(self::EXC_C14N)])]);

        $reference = $this->childrenByLocalName($signedInfo, 'Reference')[0];
        static::assertSame('#Body-1', $reference->getAttribute('URI'));
    }

    public function test_the_algorithm_attributes_match_the_enum_values(): void
    {
        $signedInfo = $this->build([new SignedReference('#Body-1', 'AAA=', DigestMethod::SHA256, [new SignedTransform(self::EXC_C14N)])]);

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
        $signedInfo = $this->build([new SignedReference('#Body-1', 'AAA=', DigestMethod::SHA256, [new SignedTransform(self::EXC_C14N)])]);

        $reference = $this->childrenByLocalName($signedInfo, 'Reference')[0];
        $digestMethod = $this->childrenByLocalName($reference, 'DigestMethod')[0];
        $digestValue = $this->childrenByLocalName($reference, 'DigestValue')[0];

        static::assertSame(DigestMethod::SHA256->value, $digestMethod->getAttribute('Algorithm'));
        static::assertSame('AAA=', $digestValue->textContent);
    }

    public function test_each_reference_declares_the_exclusive_c14n_transform(): void
    {
        $signedInfo = $this->build([new SignedReference('#Body-1', 'AAA=', DigestMethod::SHA256, [new SignedTransform(self::EXC_C14N)])]);

        $reference = $this->childrenByLocalName($signedInfo, 'Reference')[0];
        $transforms = $this->childrenByLocalName($reference, 'Transforms')[0];
        $transform = $this->childrenByLocalName($transforms, 'Transform')[0];

        static::assertSame(self::EXC_C14N, $transform->getAttribute('Algorithm'));
    }

    public function test_a_reference_declares_its_own_transform_not_signed_infos_canonicalization(): void
    {
        // Two separate facts the builder must not conflate. SignedInfo is canonicalized one way; each
        // reference was digested under whatever its own chain says, which for an attachment is not a
        // canonicalization at all.
        $signedInfo = $this->build(
            [new SignedReference('#Body-1', 'AAA=', DigestMethod::SHA256, [new SignedTransform(self::EXC_C14N)])],
            SignatureCanonicalization::C14N,
        );

        static::assertSame(
            SignatureCanonicalization::C14N->value,
            $this->childAt($signedInfo, 0)->getAttribute('Algorithm'),
        );
        static::assertSame(
            self::EXC_C14N,
            $this->transformOfFirstReference($signedInfo)->getAttribute('Algorithm'),
        );
    }

    public function test_a_reference_can_declare_a_chain_of_transforms(): void
    {
        $signedInfo = $this->build([new SignedReference('#Body-1', 'AAA=', DigestMethod::SHA256, [
            new SignedTransform(self::SWA_CONTENT),
            new SignedTransform(self::EXC_C14N, ['soap']),
        ])]);

        $reference = $this->childrenByLocalName($signedInfo, 'Reference')[0];
        $transforms = $this->childrenByLocalName($reference, 'Transforms')[0];
        $declared = $this->childrenByLocalName($transforms, 'Transform');

        static::assertCount(2, $declared);
        static::assertSame(self::SWA_CONTENT, $declared[0]->getAttribute('Algorithm'));
        static::assertSame(self::EXC_C14N, $declared[1]->getAttribute('Algorithm'));
        static::assertCount(0, $this->childrenByLocalName($declared[0], 'InclusiveNamespaces'));
        static::assertCount(1, $this->childrenByLocalName($declared[1], 'InclusiveNamespaces'));
    }

    public function test_a_reference_pins_the_prefixes_its_digest_was_computed_under(): void
    {
        $signedInfo = $this->build([new SignedReference('#Ts-1', 'AAA=', DigestMethod::SHA256, [new SignedTransform(self::EXC_C14N, ['wsse', 'soap'])])]);

        $transform = $this->transformOfFirstReference($signedInfo);
        $inclusive = $this->childrenByLocalName($transform, 'InclusiveNamespaces')[0];

        static::assertSame(self::EXC_C14N, $inclusive->namespaceURI);
        static::assertSame('wsse soap', $inclusive->getAttribute('PrefixList'));
    }

    public function test_a_reference_with_nothing_to_pin_declares_no_inclusive_namespaces(): void
    {
        $signedInfo = $this->build([new SignedReference('#Body-1', 'AAA=', DigestMethod::SHA256, [new SignedTransform(self::EXC_C14N)])]);

        static::assertSame([], $this->childrenByLocalName($this->transformOfFirstReference($signedInfo), 'InclusiveNamespaces'));
    }

    public function test_the_canonicalization_method_pins_the_prefixes_signed_info_is_canonicalized_under(): void
    {
        $signedInfo = $this->build([new SignedReference('#Body-1', 'AAA=', DigestMethod::SHA256, [new SignedTransform(self::EXC_C14N)])], prefixes: ['soap']);

        $inclusive = $this->childrenByLocalName($this->childAt($signedInfo, 0), 'InclusiveNamespaces')[0];

        static::assertSame(self::EXC_C14N, $inclusive->namespaceURI);
        static::assertSame('soap', $inclusive->getAttribute('PrefixList'));
    }

    public function test_it_pins_no_prefixes_on_signed_info_when_it_was_given_none(): void
    {
        // Whether an inclusive canonicalization may carry a PrefixList at all is settled before this point,
        // where the transform is built and the canonicalization is known: see DigestCalculatorTest. The
        // builder emits what it is handed.
        $signedInfo = $this->build(
            [new SignedReference('#Ts-1', 'AAA=', DigestMethod::SHA256, [new SignedTransform(self::EXC_C14N)])],
            SignatureCanonicalization::C14N,
        );

        static::assertSame([], $this->childrenByLocalName($this->childAt($signedInfo, 0), 'InclusiveNamespaces'));
        static::assertSame([], $this->childrenByLocalName($this->transformOfFirstReference($signedInfo), 'InclusiveNamespaces'));
    }

    private function transformOfFirstReference(Element $signedInfo): Element
    {
        $reference = $this->childrenByLocalName($signedInfo, 'Reference')[0];
        $transforms = $this->childrenByLocalName($reference, 'Transforms')[0];

        return $this->childrenByLocalName($transforms, 'Transform')[0];
    }

    /**
     * @param non-empty-list<DigestResult> $results
     * @param list<string>                 $prefixes
     */
    private function build(
        array $results,
        SignatureCanonicalization $canonicalization = SignatureCanonicalization::EXC_C14N,
        array $prefixes = [],
    ): Element {
        return (new SignedInfoBuilder())->build(
            Document::fromXmlString('<root/>'),
            $canonicalization,
            SignatureMethod::RSA_SHA256,
            $results,
            $prefixes,
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
