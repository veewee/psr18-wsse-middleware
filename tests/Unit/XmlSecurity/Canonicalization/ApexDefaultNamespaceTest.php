<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Canonicalization;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\ApexDefaultNamespace;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\CanonicalizationFailed;

final class ApexDefaultNamespaceTest extends TestCase
{
    public function test_it_declares_the_empty_default_namespace_when_the_apex_declares_none(): void
    {
        static::assertSame(
            '<wsse:Token xmlns="" xmlns:wsse="urn:wsse">body</wsse:Token>',
            ApexDefaultNamespace::emptied('<wsse:Token xmlns:wsse="urn:wsse">body</wsse:Token>'),
        );
    }

    public function test_it_declares_it_ahead_of_every_prefixed_declaration(): void
    {
        // Canonical order puts the default namespace first, so inserting it anywhere else would produce bytes
        // no canonicalization ever emits.
        $result = ApexDefaultNamespace::emptied('<a:X xmlns:a="urn:a" xmlns:b="urn:b"/>');

        static::assertSame('<a:X xmlns="" xmlns:a="urn:a" xmlns:b="urn:b"/>', $result);
    }

    public function test_it_replaces_an_inherited_default_namespace_with_the_empty_one(): void
    {
        // The emitting side states the default namespace on the apex and has already accounted for the
        // inherited one, so an inherited value is replaced rather than kept. Verified against the oracle: a
        // token inheriting a default namespace digests as though none applied.
        static::assertSame(
            '<Token xmlns="" xmlns:wsu="urn:wsu">body</Token>',
            ApexDefaultNamespace::emptied('<Token xmlns="urn:default" xmlns:wsu="urn:wsu">body</Token>'),
        );
    }

    public function test_it_leaves_an_already_empty_declaration_alone(): void
    {
        $canonical = '<Token xmlns="" xmlns:wsu="urn:wsu">body</Token>';

        static::assertSame($canonical, ApexDefaultNamespace::emptied($canonical));
    }

    public function test_it_does_not_touch_a_default_declaration_on_a_descendant(): void
    {
        // Only the apex declaration is the transform's concern; a nested one is content.
        static::assertSame(
            '<a:X xmlns="" xmlns:a="urn:a"><b xmlns="urn:inner"/></a:X>',
            ApexDefaultNamespace::emptied('<a:X xmlns:a="urn:a"><b xmlns="urn:inner"/></a:X>'),
        );
    }

    public function test_it_does_not_mistake_a_prefixed_declaration_for_a_default_one(): void
    {
        // 'xmlns:wsse' starts with 'xmlns' and must not read as a default declaration.
        $result = ApexDefaultNamespace::emptied('<wsse:Token xmlns:wsse="urn:wsse"/>');

        static::assertSame('<wsse:Token xmlns="" xmlns:wsse="urn:wsse"/>', $result);
    }

    public function test_it_handles_an_apex_with_no_declarations_at_all(): void
    {
        static::assertSame('<Token xmlns=""/>', ApexDefaultNamespace::emptied('<Token/>'));
    }

    public function test_it_handles_an_apex_whose_first_thing_is_an_attribute(): void
    {
        static::assertSame(
            '<Token xmlns="" Id="x">body</Token>',
            ApexDefaultNamespace::emptied('<Token Id="x">body</Token>'),
        );
    }

    public function test_it_refuses_a_canonical_form_that_is_not_an_element(): void
    {
        $this->expectException(CanonicalizationFailed::class);
        ApexDefaultNamespace::emptied('not an element');
    }

    public function test_it_refuses_an_empty_looking_start_tag(): void
    {
        $this->expectException(CanonicalizationFailed::class);
        ApexDefaultNamespace::emptied('<>');
    }
}
