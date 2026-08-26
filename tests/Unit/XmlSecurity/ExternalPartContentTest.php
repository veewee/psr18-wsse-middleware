<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartContent;

final class ExternalPartContentTest extends TestCase
{
    #[DataProvider('xmlMediaTypes')]
    public function test_it_recognises_the_media_types_a_peer_treats_as_xml(string $mimeType): void
    {
        static::assertTrue(ExternalPartContent::isXml($mimeType));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function xmlMediaTypes(): iterable
    {
        yield 'text/xml' => ['text/xml'];
        yield 'application/xml' => ['application/xml'];
        yield 'with parameters' => ['text/xml;charset=utf-8'];
        yield 'a +xml suffix under application' => ['application/soap+xml'];
        yield 'a +xml suffix under image' => ['image/svg+xml'];
    }

    #[DataProvider('nonXmlMediaTypes')]
    public function test_it_leaves_every_other_media_type_to_the_other_two_rules(string $mimeType): void
    {
        static::assertFalse(ExternalPartContent::isXml($mimeType));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function nonXmlMediaTypes(): iterable
    {
        yield 'plain text' => ['text/plain'];
        yield 'binary' => ['application/pdf'];
        // The suffix counts only under application and image, which is the set a peer treats as XML.
        yield 'a +xml suffix under text' => ['text/vnd.example+xml'];
        yield 'xml as a prefix of something else' => ['application/xml-dtd'];
    }

    #[DataProvider('lineEndings')]
    public function test_it_normalises_every_line_ending_of_a_text_part_to_crlf(
        string $content,
        string $expected,
    ): void {
        static::assertSame($expected, ExternalPartContent::canonicalize('text/plain', $content));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function lineEndings(): iterable
    {
        yield 'a bare LF' => ["a\nb", "a\r\nb"];
        yield 'a bare CR' => ["a\rb", "a\r\nb"];
        yield 'a CRLF already' => ["a\r\nb", "a\r\nb"];
        yield 'the three mixed' => ["a\nb\rc\r\nd", "a\r\nb\r\nc\r\nd"];
        yield 'a CR ending the content' => ["a\r", "a\r\n"];
        yield 'an LF ending the content' => ["a\n", "a\r\n"];
        yield 'two bare LFs' => ["a\n\nb", "a\r\n\r\nb"];
        // LF then CR is two breaks, not one: only a CR *followed by* an LF is the pair.
        yield 'an LF then a CR' => ["a\n\rb", "a\r\n\r\nb"];
        yield 'no line ending at all' => ['abc', 'abc'];
        yield 'empty content' => ['', ''];
    }

    public function test_it_normalises_whatever_case_and_parameters_the_media_type_carries(): void
    {
        static::assertSame("a\r\nb", ExternalPartContent::canonicalize('TEXT/Plain; charset=UTF-8', "a\nb"));
    }

    public function test_it_hands_back_a_binary_part_exactly_as_it_travelled(): void
    {
        // A peer digests these octets verbatim, so touching a line ending here would be a step the signer
        // never took, and the digest would be one only this package can reproduce.
        $binary = "%PDF-1.7\n\rbinary\r\n\x00\x1a";

        static::assertSame($binary, ExternalPartContent::canonicalize('application/pdf', $binary));
    }
}
