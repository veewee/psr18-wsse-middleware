<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Xml;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\SecurityTokenReferenceTransform;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use VeeWee\Xml\Dom\Document;

final class SecurityTokenReferenceTransformTest extends TestCase
{
    private const SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';
    private const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    private const SAML20 = 'urn:oasis:names:tc:SAML:2.0:assertion';
    private const SAML11 = 'urn:oasis:names:tc:SAML:1.0:assertion';
    private const SAML20_VALUE_TYPE = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID';
    private const SAML11_VALUE_TYPE = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID';
    private const SKI_VALUE_TYPE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier';
    private const THUMBPRINT_VALUE_TYPE = 'http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1';

    private const BST = '<wsse:BinarySecurityToken wsu:Id="bst-1">Y2VydA==</wsse:BinarySecurityToken>';

    public function test_it_claims_the_wss_str_transform_algorithm(): void
    {
        static::assertSame(
            'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform',
            (new SecurityTokenReferenceTransform())->algorithm(),
        );
    }

    public function test_it_dereferences_a_direct_reference_to_the_binary_security_token(): void
    {
        $result = $this->dereference(self::BST.$this->str('<wsse:Reference URI="#bst-1"/>'));

        static::assertSame('BinarySecurityToken', $result->element->localName);
        static::assertSame('bst-1', $result->element->getAttributeNS(self::WSU, 'Id'));
    }

    public function test_it_reports_the_canonicalization_the_transformation_parameters_name(): void
    {
        $result = $this->dereference(self::BST.$this->str('<wsse:Reference URI="#bst-1"/>'));

        static::assertSame(SignatureCanonicalization::EXC_C14N, $result->canonicalization);
    }

    public function test_it_reports_an_inclusive_canonicalization_a_peer_named(): void
    {
        // Whether an inclusive method is acceptable is the policy enforcer's call, not this one's: reporting it
        // faithfully is what lets the existing allow-list refuse it.
        $result = $this->dereference(
            self::BST.$this->str('<wsse:Reference URI="#bst-1"/>'),
            canonicalization: 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
        );

        static::assertSame(SignatureCanonicalization::C14N, $result->canonicalization);
    }

    public function test_it_always_pins_the_default_namespace_prefix(): void
    {
        // WSS4J canonicalizes the dereferenced token with a hardcoded '#default' inclusive prefix, so a
        // verifier that leaves it out digests different bytes than the signer did.
        $result = $this->dereference(self::BST.$this->str('<wsse:Reference URI="#bst-1"/>'));

        static::assertSame(['#default'], $result->inclusivePrefixes);
    }

    public function test_it_keeps_a_declared_prefix_list_alongside_the_default(): void
    {
        $result = $this->dereference(
            self::BST.$this->str('<wsse:Reference URI="#bst-1"/>'),
            prefixList: 'soap wsu',
        );

        static::assertContains('#default', $result->inclusivePrefixes);
        static::assertContains('soap', $result->inclusivePrefixes);
        static::assertContains('wsu', $result->inclusivePrefixes);
    }

    public function test_it_does_not_repeat_the_default_prefix_a_peer_already_listed(): void
    {
        $result = $this->dereference(
            self::BST.$this->str('<wsse:Reference URI="#bst-1"/>'),
            prefixList: '#default soap',
        );

        static::assertSame(['#default', 'soap'], $result->inclusivePrefixes);
    }

    public function test_it_dereferences_a_saml_20_key_identifier_to_the_assertion(): void
    {
        $result = $this->dereference(
            '<saml:Assertion xmlns:saml="'.self::SAML20.'" ID="assertion-1"/>'
            .$this->str(
                '<wsse:KeyIdentifier ValueType="'.self::SAML20_VALUE_TYPE.'">assertion-1</wsse:KeyIdentifier>',
            ),
        );

        static::assertSame('Assertion', $result->element->localName);
        static::assertSame(self::SAML20, $result->element->namespaceURI);
    }

    public function test_it_dereferences_a_saml_11_key_identifier_by_its_own_id_attribute(): void
    {
        $result = $this->dereference(
            '<saml:Assertion xmlns:saml="'.self::SAML11.'" AssertionID="assertion-1"/>'
            .$this->str(
                '<wsse:KeyIdentifier ValueType="'.self::SAML11_VALUE_TYPE.'">assertion-1</wsse:KeyIdentifier>',
            ),
        );

        static::assertSame('Assertion', $result->element->localName);
        static::assertSame(self::SAML11, $result->element->namespaceURI);
    }

    public function test_it_refuses_a_saml_key_identifier_naming_an_assertion_of_another_version(): void
    {
        // The value type states which version, and therefore which attribute carries the id. An assertion of
        // the other version is not the token the reference described.
        $this->expectException(SignatureVerificationFailed::class);
        $this->dereference(
            '<saml:Assertion xmlns:saml="'.self::SAML11.'" AssertionID="assertion-1"/>'
            .$this->str(
                '<wsse:KeyIdentifier ValueType="'.self::SAML20_VALUE_TYPE.'">assertion-1</wsse:KeyIdentifier>',
            ),
        );
    }

    public function test_it_refuses_a_saml_key_identifier_when_two_assertions_carry_the_id(): void
    {
        $this->expectException(SignatureVerificationFailed::class);
        $this->dereference(
            '<saml:Assertion xmlns:saml="'.self::SAML20.'" ID="assertion-1"/>'
            .'<saml:Assertion xmlns:saml="'.self::SAML20.'" ID="assertion-1"/>'
            .$this->str(
                '<wsse:KeyIdentifier ValueType="'.self::SAML20_VALUE_TYPE.'">assertion-1</wsse:KeyIdentifier>',
            ),
        );
    }

    public function test_it_refuses_a_subject_key_identifier(): void
    {
        // WSS4J digests a BinarySecurityToken it synthesizes from its own keystore for this form. That phantom
        // element is not reproduced here, so the reference is refused rather than approximated.
        $this->expectException(SignatureVerificationFailed::class);
        $this->dereference(
            self::BST.$this->str(
                '<wsse:KeyIdentifier ValueType="'.self::SKI_VALUE_TYPE.'">c2tp</wsse:KeyIdentifier>',
            ),
        );
    }

    public function test_it_refuses_a_thumbprint_key_identifier(): void
    {
        $this->expectException(SignatureVerificationFailed::class);
        $this->dereference(
            self::BST.$this->str(
                '<wsse:KeyIdentifier ValueType="'.self::THUMBPRINT_VALUE_TYPE.'">dGh1bWI=</wsse:KeyIdentifier>',
            ),
        );
    }

    public function test_it_refuses_an_issuer_serial_reference(): void
    {
        $this->expectException(SignatureVerificationFailed::class);
        $this->dereference(
            $this->str(
                '<ds:X509Data xmlns:ds="'.self::DS.'"><ds:X509IssuerSerial>'
                .'<ds:X509IssuerName>CN=Issuer</ds:X509IssuerName><ds:X509SerialNumber>1</ds:X509SerialNumber>'
                .'</ds:X509IssuerSerial></ds:X509Data>',
            ),
        );
    }

    public function test_it_refuses_a_transform_with_no_transformation_parameters(): void
    {
        // WSS4J would fail on a null canonicalization here. Nothing can be digested without knowing how.
        $this->expectException(SignatureVerificationFailed::class);
        $this->dereference(self::BST.$this->str('<wsse:Reference URI="#bst-1"/>'), transformationParameters: '');
    }

    public function test_it_refuses_transformation_parameters_naming_no_canonicalization(): void
    {
        $this->expectException(SignatureVerificationFailed::class);
        $this->dereference(
            self::BST.$this->str('<wsse:Reference URI="#bst-1"/>'),
            transformationParameters: '<wsse:TransformationParameters/>',
        );
    }

    public function test_it_refuses_two_canonicalization_methods(): void
    {
        // A duplicate reads as absent, so an injected sibling cannot decide which method the digest used.
        $this->expectException(SignatureVerificationFailed::class);
        $this->dereference(
            self::BST.$this->str('<wsse:Reference URI="#bst-1"/>'),
            transformationParameters:
                '<wsse:TransformationParameters>'
                .'<ds:CanonicalizationMethod xmlns:ds="'.self::DS.'" Algorithm="'.self::EXC_C14N.'"/>'
                .'<ds:CanonicalizationMethod xmlns:ds="'.self::DS.'" Algorithm="'.self::EXC_C14N.'"/>'
                .'</wsse:TransformationParameters>',
        );
    }

    public function test_it_refuses_an_unknown_canonicalization(): void
    {
        $this->expectException(SignatureVerificationFailed::class);
        $this->dereference(
            self::BST.$this->str('<wsse:Reference URI="#bst-1"/>'),
            canonicalization: 'urn:not-a-canonicalization',
        );
    }

    public function test_it_refuses_a_reference_that_names_no_supported_form(): void
    {
        $this->expectException(SignatureVerificationFailed::class);
        $this->dereference($this->str('<wsse:Embedded/>'));
    }

    public function test_it_refuses_an_empty_reference(): void
    {
        $this->expectException(SignatureVerificationFailed::class);
        $this->dereference($this->str(''));
    }

    public function test_it_refuses_two_direct_references(): void
    {
        $this->expectException(SignatureVerificationFailed::class);
        $this->dereference(
            self::BST.$this->str('<wsse:Reference URI="#bst-1"/><wsse:Reference URI="#bst-1"/>'),
        );
    }

    public function test_it_refuses_a_reference_that_resolves_to_another_reference(): void
    {
        // A chain would let a peer point the digest at a token one indirection further away than the signature
        // declares, so it is refused rather than followed.
        $this->expectException(SignatureVerificationFailed::class);
        $this->dereference(
            '<wsse:SecurityTokenReference wsu:Id="str-2"><wsse:Reference URI="#bst-1"/></wsse:SecurityTokenReference>'
            .$this->str('<wsse:Reference URI="#str-2"/>'),
        );
    }

    public function test_it_refuses_a_reference_that_resolves_to_itself(): void
    {
        $this->expectException(SignatureVerificationFailed::class);
        $this->dereference($this->str('<wsse:Reference URI="#str-1"/>'));
    }

    public function test_it_refuses_an_unresolvable_reference(): void
    {
        $this->expectException(SignatureVerificationFailed::class);
        $this->dereference($this->str('<wsse:Reference URI="#missing"/>'));
    }

    public function test_it_refuses_a_reference_that_is_not_a_same_document_id(): void
    {
        $this->expectException(SignatureVerificationFailed::class);
        $this->dereference($this->str('<wsse:Reference URI="https://evil.example/token"/>'));
    }

    public function test_it_refuses_a_duplicated_target_id(): void
    {
        $this->expectException(SignatureVerificationFailed::class);
        $this->dereference(
            self::BST
            .'<wsse:BinarySecurityToken wsu:Id="bst-1">b3RoZXI=</wsse:BinarySecurityToken>'
            .$this->str('<wsse:Reference URI="#bst-1"/>'),
        );
    }

    /**
     * @param string|null $transformationParameters the markup inside ds:Transform; null builds the ordinary
     *        wsse:TransformationParameters naming $canonicalization, '' leaves the transform empty
     */
    private function dereference(
        string $securityChildren,
        ?string $transformationParameters = null,
        string $canonicalization = self::EXC_C14N,
        string $prefixList = '',
    ): Result {
        $parameters = $transformationParameters ?? $this->transformationParameters($canonicalization, $prefixList);
        $document = $this->envelope($securityChildren, $parameters);
        $transform = new SecurityTokenReferenceTransform();
        $transformElement = $this->only($document, self::DS, 'Transform');

        // Both halves of the SPI, in the order the verifier calls them: the canonicalization is read before
        // anything is resolved, so an unusable one is refused before a reference is followed.
        $how = $transform->canonicalization($transformElement);
        $element = $transform->dereference(
            $document,
            $this->only($document, self::WSSE, 'SecurityTokenReference'),
            $transformElement,
            (new WsuIdConvention())->lookup(),
        );

        return new Result($element, $how->canonicalization, $how->inclusivePrefixes);
    }

    private function transformationParameters(string $canonicalization, string $prefixList): string
    {
        $inclusive = $prefixList === ''
            ? ''
            : '<ec:InclusiveNamespaces xmlns:ec="'.self::EXC_C14N.'" PrefixList="'.$prefixList.'"/>';

        return '<wsse:TransformationParameters>'
            .'<ds:CanonicalizationMethod xmlns:ds="'.self::DS.'" Algorithm="'.$canonicalization.'">'
            .$inclusive
            .'</ds:CanonicalizationMethod>'
            .'</wsse:TransformationParameters>';
    }

    private function str(string $children): string
    {
        return '<wsse:SecurityTokenReference wsu:Id="str-1">'.$children.'</wsse:SecurityTokenReference>';
    }

    /**
     * The realistic shape: the reference lives in the Security header and the transform that dereferences it
     * lives in the signature's own ds:Reference, exactly where a WSS4J peer puts them.
     */
    private function envelope(string $securityChildren, string $transformationParameters): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP.'" xmlns:wsse="'.self::WSSE.'" xmlns:wsu="'.self::WSU.'">'
            .'<soap:Header><wsse:Security>'
            .$securityChildren
            .'<ds:Signature xmlns:ds="'.self::DS.'"><ds:SignedInfo><ds:Reference URI="#str-1"><ds:Transforms>'
            .'<ds:Transform Algorithm="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform">'
            .$transformationParameters
            .'</ds:Transform></ds:Transforms></ds:Reference></ds:SignedInfo></ds:Signature>'
            .'</wsse:Security></soap:Header>'
            .'<soap:Body><data>x</data></soap:Body></soap:Envelope>',
        );
    }

    private function only(Document $document, string $namespace, string $localName): Element
    {
        $found = $document->toUnsafeDocument()->getElementsByTagNameNS($namespace, $localName)->item(0);
        static::assertInstanceOf(Element::class, $found);

        return $found;
    }
}

/**
 * The two answers the transform gives, held together so each test can assert on either.
 */
final readonly class Result
{
    /**
     * @param list<string> $inclusivePrefixes
     */
    public function __construct(
        public Element $element,
        public SignatureCanonicalization $canonicalization,
        public array $inclusivePrefixes,
    ) {
    }
}
