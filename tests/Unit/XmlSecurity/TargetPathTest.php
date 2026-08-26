<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\Xml\QualifiedName;
use Soap\Psr18WsseMiddleware\XmlSecurity\Target;
use Soap\Psr18WsseMiddleware\XmlSecurity\TargetKind;
use Soap\Psr18WsseMiddleware\XmlSecurity\TargetLocator;
use VeeWee\Xml\Dom\Document;

/**
 * A path target names the element by where it sits, not only by what it is called. Each step is resolved
 * among the direct children of the previous one and must match exactly one, so an element carrying the right
 * name somewhere else in the document never satisfies it.
 */
final class TargetPathTest extends TestCase
{
    private const SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    private const APP = 'urn:app';

    public function test_a_path_target_reports_its_kind_and_steps(): void
    {
        $target = Target::path(
            new QualifiedName(self::SOAP, 'Envelope'),
            new QualifiedName(self::SOAP, 'Body'),
        );

        static::assertSame(TargetKind::Path, $target->kind());
        static::assertCount(2, $target->steps());
        static::assertSame('Body', $target->steps()[1]->localName);
    }

    public function test_it_resolves_the_element_at_the_path(): void
    {
        $document = $this->envelope('<soap:Body><app:Payload>real</app:Payload></soap:Body>');

        $located = (new TargetLocator())->locate($document, $this->bodyPath());

        static::assertSame('Body', $located->localName);
        static::assertStringContainsString('real', $located->textContent);
    }

    /**
     * The whole point: a look-alike parked elsewhere is not the element the path names, even when it is the
     * only one in the document.
     */
    public function test_an_element_of_the_right_name_elsewhere_does_not_satisfy_the_path(): void
    {
        $document = $this->envelope('<soap:Header><wrap><soap:Body>relocated</soap:Body></wrap></soap:Header>');

        $this->expectException(IdReferenceException::class);
        (new TargetLocator())->locate($document, $this->bodyPath());
    }

    public function test_a_duplicated_step_is_refused_as_ambiguous(): void
    {
        $document = $this->envelope('<soap:Body>one</soap:Body><soap:Body>two</soap:Body>');

        $this->expectException(IdReferenceException::class);
        $this->expectExceptionMessage('ambiguous');
        (new TargetLocator())->locate($document, $this->bodyPath());
    }

    public function test_a_missing_step_is_refused_as_absent(): void
    {
        $document = $this->envelope('<soap:Header/>');

        $this->expectException(IdReferenceException::class);
        $this->expectExceptionMessage('No element found');
        (new TargetLocator())->locate($document, $this->bodyPath());
    }

    /**
     * The first step names the document element itself, so a path is only satisfied inside the document shape
     * it describes.
     */
    public function test_a_document_element_that_does_not_match_the_first_step_is_refused(): void
    {
        $document = Document::fromXmlString('<other xmlns="'.self::SOAP.'"><Body/></other>');

        $this->expectException(IdReferenceException::class);
        (new TargetLocator())->locate($document, $this->bodyPath());
    }

    public function test_a_path_reaches_an_element_nested_several_levels_deep(): void
    {
        $document = $this->envelope('<soap:Body><app:Order><app:Total>42</app:Total></app:Order></soap:Body>');

        $located = (new TargetLocator())->locate($document, Target::path(
            new QualifiedName(self::SOAP, 'Envelope'),
            new QualifiedName(self::SOAP, 'Body'),
            new QualifiedName(self::APP, 'Order'),
            new QualifiedName(self::APP, 'Total'),
        ));

        static::assertSame('Total', $located->localName);
        static::assertSame('42', $located->textContent);
    }

    /**
     * A step matches only the full qualified name, so an element sharing the local name in another namespace
     * is not a candidate.
     */
    public function test_a_step_does_not_match_the_same_local_name_in_another_namespace(): void
    {
        $document = $this->envelope('<Body xmlns="urn:not-soap">decoy</Body>');

        $this->expectException(IdReferenceException::class);
        (new TargetLocator())->locate($document, $this->bodyPath());
    }

    public function test_paths_compare_by_their_steps(): void
    {
        $body = $this->bodyPath();
        $same = Target::path(new QualifiedName(self::SOAP, 'Envelope'), new QualifiedName(self::SOAP, 'Body'));
        $header = Target::path(new QualifiedName(self::SOAP, 'Envelope'), new QualifiedName(self::SOAP, 'Header'));
        $shorter = Target::path(new QualifiedName(self::SOAP, 'Envelope'));

        static::assertTrue($body->equals($same));
        static::assertFalse($body->equals($header));
        static::assertFalse($body->equals($shorter));
        static::assertFalse($body->equals(Target::element(self::SOAP, 'Body')));
    }

    private function bodyPath(): Target
    {
        return Target::path(
            new QualifiedName(self::SOAP, 'Envelope'),
            new QualifiedName(self::SOAP, 'Body'),
        );
    }

    private function envelope(string $innerXml): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP.'" xmlns:app="'.self::APP.'">'.$innerXml.'</soap:Envelope>',
        );
    }
}
