<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Xml\Locator;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator\Fault;
use VeeWee\Xml\Dom\Document;

final class FaultTest extends TestCase
{
    private const SOAP11 = 'http://schemas.xmlsoap.org/soap/envelope/';
    private const SOAP12 = 'http://www.w3.org/2003/05/soap-envelope';

    public function test_it_reads_a_soap11_fault(): void
    {
        $fault = (new Fault())->locate(
            $this->envelope(
                self::SOAP11,
                '<soap:Fault><faultcode>soap:Client</faultcode>'
                .'<faultstring>Invalid security token</faultstring></soap:Fault>',
            ),
            SoapVersion::Soap11,
        );

        static::assertNotNull($fault);
        static::assertSame('soap:Client', $fault->code);
        static::assertSame('Invalid security token', $fault->reason);
    }

    public function test_it_reads_a_soap12_fault(): void
    {
        $fault = (new Fault())->locate(
            $this->envelope(
                self::SOAP12,
                '<soap:Fault><soap:Code><soap:Value>soap:Sender</soap:Value></soap:Code>'
                .'<soap:Reason><soap:Text xml:lang="en">Invalid security token</soap:Text></soap:Reason>'
                .'</soap:Fault>',
            ),
            SoapVersion::Soap12,
        );

        static::assertNotNull($fault);
        static::assertSame('soap:Sender', $fault->code);
        static::assertSame('Invalid security token', $fault->reason);
    }

    public function test_it_reports_nothing_for_a_response_that_is_not_a_fault(): void
    {
        $fault = (new Fault())->locate(
            $this->envelope(self::SOAP12, '<result>ok</result>'),
            SoapVersion::Soap12,
        );

        static::assertNull($fault);
    }

    public function test_it_does_not_read_a_fault_outside_the_body(): void
    {
        // A fault-shaped element planted in the header is not the response's fault, and treating it as one
        // would let a peer choose the text an operator reads.
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'">'
            .'<soap:Header><soap:Fault><soap:Code><soap:Value>soap:Sender</soap:Value></soap:Code>'
            .'<soap:Reason><soap:Text>planted</soap:Text></soap:Reason></soap:Fault></soap:Header>'
            .'<soap:Body><result>ok</result></soap:Body></soap:Envelope>',
        );

        static::assertNull((new Fault())->locate($document, SoapVersion::Soap12));
    }

    public function test_it_reports_nothing_when_the_body_holds_more_than_one_fault(): void
    {
        // Two faults leave no single answer, and picking one is a verdict a peer steers.
        $document = $this->envelope(
            self::SOAP11,
            '<soap:Fault><faultcode>soap:Client</faultcode><faultstring>first</faultstring></soap:Fault>'
            .'<soap:Fault><faultcode>soap:Server</faultcode><faultstring>second</faultstring></soap:Fault>',
        );

        static::assertNull((new Fault())->locate($document, SoapVersion::Soap11));
    }

    public function test_it_reads_a_fault_that_states_neither_code_nor_reason(): void
    {
        // Both children are optional in the schema. The fault is still the reason the response failed, so it
        // is reported with what it carries rather than discarded.
        $fault = (new Fault())->locate(
            $this->envelope(self::SOAP11, '<soap:Fault/>'),
            SoapVersion::Soap11,
        );

        static::assertNotNull($fault);
        static::assertSame('', $fault->code);
        static::assertSame('', $fault->reason);
    }

    public function test_it_strips_control_characters_from_peer_text(): void
    {
        $fault = (new Fault())->locate(
            $this->envelope(
                self::SOAP11,
                "<soap:Fault><faultcode>soap:Client</faultcode>"
                .'<faultstring>line&#13;&#10;break&#9;tab</faultstring></soap:Fault>',
            ),
            SoapVersion::Soap11,
        );

        static::assertNotNull($fault);
        static::assertSame('line break tab', $fault->reason);
    }

    public function test_it_caps_the_length_of_peer_text(): void
    {
        $fault = (new Fault())->locate(
            $this->envelope(
                self::SOAP11,
                '<soap:Fault><faultcode>soap:Client</faultcode>'
                .'<faultstring>'.str_repeat('a', 500).'</faultstring></soap:Fault>',
            ),
            SoapVersion::Soap11,
        );

        static::assertNotNull($fault);
        static::assertSame(200, mb_strlen($fault->reason));
    }

    private function envelope(string $namespace, string $bodyChildren): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.$namespace.'">'
            .'<soap:Body>'.$bodyChildren.'</soap:Body></soap:Envelope>',
        );
    }
}
