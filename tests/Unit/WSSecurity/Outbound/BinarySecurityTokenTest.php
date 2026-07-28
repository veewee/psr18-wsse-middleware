<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound;

use Dom\Element;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\CertificateChain;
use Soap\Psr18WsseMiddleware\KeyStore\PkiPath;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\BinarySecurityToken;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Timestamp;
use SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\WsseSignatureFixture;

final class BinarySecurityTokenTest extends OutboundTestCase
{
    private const X509V3 = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3';
    private const X509_PKI_PATH = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509PKIPathv1';
    private const WSSE11 = 'http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd';
    private const BASE64_BINARY ='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary';

    private function certificate(): Certificate
    {
        return Certificate::fromFile(FIXTURE_DIR.'/certificates/wsse-client-x509.pem');
    }

    private function chain(): CertificateChain
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();

        return CertificateChain::fromCertificates($fixture->leafCertificate, $fixture->caCertificate);
    }

    public function test_it_adds_a_binary_security_token_to_the_security_header(): void
    {
        $document = $this->envelope();

        (new BinarySecurityToken($this->certificate()))($this->context($document));

        $security = $this->only($document, self::WSSE, 'Security');
        $bst = $this->only($document, self::WSSE, 'BinarySecurityToken');
        static::assertSame($security, $bst->parentNode);
    }

    public function test_value_type_is_x509v3(): void
    {
        $document = $this->envelope();

        (new BinarySecurityToken($this->certificate()))($this->context($document));

        static::assertSame(self::X509V3, $this->only($document, self::WSSE, 'BinarySecurityToken')->getAttribute('ValueType'));
    }

    public function test_encoding_type_is_base64_binary(): void
    {
        $document = $this->envelope();

        (new BinarySecurityToken($this->certificate()))($this->context($document));

        static::assertSame(self::BASE64_BINARY, $this->only($document, self::WSSE, 'BinarySecurityToken')->getAttribute('EncodingType'));
    }

    public function test_body_is_the_base64_der_of_the_certificate(): void
    {
        $document = $this->envelope();

        (new BinarySecurityToken($this->certificate()))($this->context($document));

        $body = $this->only($document, self::WSSE, 'BinarySecurityToken')->textContent;
        $der = base64_decode($body, true);
        static::assertNotFalse($der);

        $expectedPem = preg_replace('/-----[^-]+-----|\s/', '', $this->certificate()->contents());
        static::assertSame($expectedPem, base64_encode($der));
    }

    public function test_the_token_carries_a_minted_wsu_id(): void
    {
        $document = $this->envelope();

        (new BinarySecurityToken($this->certificate()))($this->context($document));

        $id = $this->only($document, self::WSSE, 'BinarySecurityToken')->getAttributeNS(self::WSU, 'Id');
        static::assertMatchesRegularExpression('/^id-[0-9a-f-]{36}$/', $id);
    }

    public function test_embedding_the_same_certificate_twice_reuses_one_token(): void
    {
        $document = $this->envelope();
        $context = $this->context($document);
        $token = new BinarySecurityToken($this->certificate());

        $first = $token->embed($context);
        $second = $token->embed($context);

        static::assertCount(1, $this->elements($document, self::WSSE, 'BinarySecurityToken'));
        static::assertSame($first, $second);
    }

    public function test_it_embeds_the_token_and_returns_a_direct_reference_to_it(): void
    {
        $document = $this->envelope();

        $identifier = (new BinarySecurityToken($this->certificate()))->embedAsDirectReference($this->context($document));

        $bst = $this->only($document, self::WSSE, 'BinarySecurityToken');
        $keyInfo = $identifier->apply($document, $this->certificate());
        $reference = $keyInfo->getElementsByTagNameNS(self::WSSE, 'Reference')->item(0);

        static::assertInstanceOf(Element::class, $reference);
        static::assertSame('#'.$bst->getAttributeNS(self::WSU, 'Id'), $reference->getAttribute('URI'));
        static::assertSame(self::X509V3, $reference->getAttribute('ValueType'));
    }

    public function test_a_certificate_path_token_declares_the_pkipath_value_type(): void
    {
        $document = $this->envelope();

        BinarySecurityToken::forCertificatePath($this->chain())($this->context($document));

        static::assertSame(self::X509_PKI_PATH, $this->only($document, self::WSSE, 'BinarySecurityToken')->getAttribute('ValueType'));
    }

    public function test_a_certificate_path_token_body_carries_the_whole_path(): void
    {
        $document = $this->envelope();
        $chain = $this->chain();

        BinarySecurityToken::forCertificatePath($chain)($this->context($document));

        $body = $this->only($document, self::WSSE, 'BinarySecurityToken')->textContent;
        $der = base64_decode($body, true);
        static::assertIsString($der);
        static::assertSame(PkiPath::encode($chain), $der);

        // Read back through the inbound parser: both certificates arrive, and the anchor is emitted first.
        $carried = PkiPath::certificates($der);
        static::assertCount(2, $carried);
        static::assertSame($chain->all()[1]->toBase64Der(), $carried[0]->toBase64Der());
        static::assertSame($chain->leaf()->toBase64Der(), $carried[1]->toBase64Der());
    }

    public function test_a_direct_reference_to_a_path_token_declares_the_pkipath_value_type(): void
    {
        $document = $this->envelope();
        $chain = $this->chain();

        $identifier = BinarySecurityToken::forCertificatePath($chain)->embedAsDirectReference($this->context($document));

        // The reference's ValueType names what the referenced token carries, so it has to move with the token's:
        // a peer that finds them disagreeing refuses the SecurityTokenReference outright.
        $keyInfo = $identifier->apply($document, $chain->leaf());
        $reference = $keyInfo->getElementsByTagNameNS(self::WSSE, 'Reference')->item(0);
        static::assertInstanceOf(Element::class, $reference);
        static::assertSame(self::X509_PKI_PATH, $reference->getAttribute('ValueType'));

        // The X.509 profile also requires a reference to a path token to name the token's type on the
        // SecurityTokenReference itself. A reference carrying only the ValueType is refused.
        $str = $keyInfo->getElementsByTagNameNS(self::WSSE, 'SecurityTokenReference')->item(0);
        static::assertInstanceOf(Element::class, $str);
        static::assertSame(self::X509_PKI_PATH, $str->getAttributeNS(self::WSSE11, 'TokenType'));
    }

    public function test_a_direct_reference_to_a_leaf_token_carries_no_token_type(): void
    {
        $document = $this->envelope();

        $identifier = (new BinarySecurityToken($this->certificate()))->embedAsDirectReference($this->context($document));

        // Only the path token needs its type named; a bare certificate reference is complete without it.
        $str = $identifier->apply($document, $this->certificate())
            ->getElementsByTagNameNS(self::WSSE, 'SecurityTokenReference')->item(0);
        static::assertInstanceOf(Element::class, $str);
        static::assertFalse($str->hasAttributeNS(self::WSSE11, 'TokenType'));
    }

    public function test_a_path_token_and_a_leaf_token_are_separate_tokens(): void
    {
        $document = $this->envelope();
        $context = $this->context($document);
        $chain = $this->chain();

        BinarySecurityToken::forCertificatePath($chain)($context);
        (new BinarySecurityToken($chain->leaf()))($context);

        // They carry different bytes under different value types, so reuse by content must not collapse them.
        static::assertCount(2, $this->elements($document, self::WSSE, 'BinarySecurityToken'));
    }

    public function test_embedding_the_same_path_twice_reuses_one_token(): void
    {
        $document = $this->envelope();
        $context = $this->context($document);
        $token = BinarySecurityToken::forCertificatePath($this->chain());

        $first = $token->embed($context);
        $second = $token->embed($context);

        static::assertCount(1, $this->elements($document, self::WSSE, 'BinarySecurityToken'));
        static::assertSame($first, $second);
    }

    public function test_the_token_precedes_a_timestamp_in_canonical_order(): void
    {
        $document = $this->envelope();
        $context = $this->context($document);

        (new Timestamp())($context);
        (new BinarySecurityToken($this->certificate()))($context);

        $security = $this->only($document, self::WSSE, 'Security');
        $order = [];
        foreach ($security->childNodes as $child) {
            if ($child instanceof Element) {
                $order[] = $child->localName;
            }
        }

        static::assertSame(['BinarySecurityToken', 'Timestamp'], $order);
    }
}
