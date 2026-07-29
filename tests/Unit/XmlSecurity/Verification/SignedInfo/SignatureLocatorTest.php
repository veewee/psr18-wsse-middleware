<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Verification\SignedInfo;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\SignatureLocator;
use VeeWee\Xml\Dom\Document;

/**
 * The locator reads the signature out of the scope its caller resolved, never out of the document. The
 * caller decides which region of the message is its own: for the WS-Security profile, the Security header
 * addressed to this receiver: so a ds:Signature sitting anywhere else belongs to another hop or was planted,
 * and must not be offered to the verifier.
 */
final class SignatureLocatorTest extends TestCase
{
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';

    public function test_it_finds_the_signature_inside_the_scope(): void
    {
        $document = $this->document(
            '<wsse:Security><ds:Signature ds:Id="ours"/></wsse:Security>',
        );

        $signature = (new SignatureLocator())->locate($this->scope($document, 0));

        static::assertSame('Signature', $signature->localName);
        static::assertSame('ours', $signature->getAttributeNS(self::DS, 'Id'));
    }

    public function test_it_refuses_a_signature_that_lives_outside_the_scope(): void
    {
        // Two Security headers: the second is another hop's. Scoped to the first, which carries none, the
        // signature in the second must not be found: document-wide it would have been the only one.
        $document = $this->document(
            '<wsse:Security/><wsse:Security><ds:Signature ds:Id="other-hop"/></wsse:Security>',
        );

        $this->expectException(SignatureVerificationFailed::class);
        (new SignatureLocator())->locate($this->scope($document, 0));
    }

    public function test_it_refuses_a_signature_planted_deeper_inside_the_scope(): void
    {
        // Only a direct child counts: a signature wrapped in another element inside our own header is not the
        // header's signature, and treating it as one would reopen the relocation shape.
        $document = $this->document(
            '<wsse:Security><wrapper><ds:Signature ds:Id="nested"/></wrapper></wsse:Security>',
        );

        $this->expectException(SignatureVerificationFailed::class);
        (new SignatureLocator())->locate($this->scope($document, 0));
    }

    public function test_it_refuses_two_signatures_in_the_scope(): void
    {
        $document = $this->document(
            '<wsse:Security><ds:Signature ds:Id="a"/><ds:Signature ds:Id="b"/></wsse:Security>',
        );

        $this->expectException(SignatureVerificationFailed::class);
        (new SignatureLocator())->locate($this->scope($document, 0));
    }

    public function test_it_refuses_a_scope_carrying_no_signature(): void
    {
        $document = $this->document('<wsse:Security/>');

        $this->expectException(SignatureVerificationFailed::class);
        (new SignatureLocator())->locate($this->scope($document, 0));
    }

    private function document(string $headerContents): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"'
            .' xmlns:wsse="'.self::WSSE.'" xmlns:ds="'.self::DS.'">'
            .'<soap:Header>'.$headerContents.'</soap:Header>'
            .'<soap:Body><data>x</data></soap:Body>'
            .'</soap:Envelope>'
        );
    }

    private function scope(Document $document, int $index): Element
    {
        $security = $document->toUnsafeDocument()->getElementsByTagNameNS(self::WSSE, 'Security')->item($index);
        static::assertInstanceOf(Element::class, $security);

        return $security;
    }
}
