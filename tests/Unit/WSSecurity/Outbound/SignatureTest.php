<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound;

use InvalidArgumentException;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\RequiresPhp;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\CertificateChain;
use Soap\Psr18WsseMiddleware\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\KeyStore\PkiPath;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\OpenSSL\Signer as OpenSslSigner;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\DirectReferenceKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\KeyRef;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\X509SubjectKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Signature;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdConvention;
use Soap\Psr18WsseMiddleware\Xml\QualifiedName;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\DomCanonicalizer;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\DigestCalculator;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\ReferenceCollector;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\SignedInfoBuilder;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\Signer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Target;
use Soap\Psr18WsseMiddleware\XmlSecurity\TargetLocator;
use SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\WsseSignatureFixture;
use VeeWee\Xml\Dom\Document;

final class SignatureTest extends OutboundTestCase
{
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';
    private const X509_PKI_PATH = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509PKIPathv1';

    public function test_it_uses_profile_algorithms_by_default(): void
    {
        $signer = new RecordingSigner();
        (new Signature($this->clientCertificate()))->withSigner($signer)($this->signableContext());

        $request = $signer->lastRequest();
        static::assertSame(SignatureMethod::RSA_SHA256, $request->signatureMethod);
        static::assertSame(DigestMethod::SHA256, $request->digestMethod);
        static::assertSame(SignatureCanonicalization::EXC_C14N, $request->canonicalization);
    }

    public function test_a_context_profile_overrides_the_default(): void
    {
        $signer = new RecordingSigner();
        $profile = new SecurityProfile(crypto: new CryptoPolicy(signatureMethod: SignatureMethod::RSA_SHA512));
        (new Signature($this->clientCertificate()))->withSigner($signer)($this->context($this->signableEnvelope(), $profile));

        static::assertSame(SignatureMethod::RSA_SHA512, $signer->lastRequest()->signatureMethod);
    }

    public function test_a_per_block_override_wins_over_the_profile(): void
    {
        $signer = new RecordingSigner();
        $block = (new Signature($this->clientCertificate()))->withSigner($signer)->withSignatureMethod(SignatureMethod::RSA_SHA1);
        $block($this->signableContext());

        static::assertSame(SignatureMethod::RSA_SHA1, $signer->lastRequest()->signatureMethod);
    }

    public function test_it_pins_no_inclusive_prefixes_by_default(): void
    {
        $signer = new RecordingSigner();
        (new Signature($this->clientCertificate()))->withSigner($signer)($this->signableContext());

        static::assertFalse($signer->lastRequest()->inclusivePrefixes);
    }

    public function test_it_pins_inclusive_prefixes_when_asked(): void
    {
        $signer = new RecordingSigner();
        $block = (new Signature($this->clientCertificate()))->withSigner($signer)->withInclusivePrefixes();
        $block($this->signableContext());

        static::assertTrue($signer->lastRequest()->inclusivePrefixes);
    }

    public function test_with_methods_are_immutable(): void
    {
        $certificate = $this->clientCertificate();
        $original = (new Signature($certificate))->withSigner(new RecordingSigner());

        static::assertNotSame($original, $original->withCertificatePath(
            CertificateChain::fromCertificates($certificate->publicCertificate()),
        ));

        static::assertNotSame($original, $original->withSignatureMethod(SignatureMethod::RSA_SHA1));
        static::assertNotSame($original, $original->withDigestMethod(DigestMethod::SHA512));
        static::assertNotSame($original, $original->withCanonicalization(SignatureCanonicalization::EXC_C14N_COMMENTS));
        static::assertNotSame($original, $original->withParts([Part::body()]));
        static::assertNotSame($original, $original->withInclusivePrefixes());
    }

    public function test_with_signer_routes_signing_to_the_given_signer(): void
    {
        $signer = new RecordingSigner();
        (new Signature($this->clientCertificate()))->withSigner($signer)($this->signableContext());

        // lastRequest() throws unless sign() ran on the injected double, proving the override is used.
        static::assertInstanceOf(SignatureMethod::class, $signer->lastRequest()->signatureMethod);
    }

    public function test_default_parts_are_body_and_the_security_header_contents(): void
    {
        $signer = new RecordingSigner();
        (new Signature($this->clientCertificate()))->withSigner($signer)($this->signableContext());

        // Default keyRef embeds a BinarySecurityToken into the Security header, so the default parts resolve to
        // the Body plus the security-header children (the embedded BST here), each targeted by id.
        $targets = $signer->lastRequest()->targets;
        static::assertTrue($targets[0]->equals(self::bodyPath()));
        static::assertGreaterThanOrEqual(2, count($targets));
        static::assertSame(\Soap\Psr18WsseMiddleware\XmlSecurity\TargetKind::Id, $targets[1]->kind());
    }

    public function test_explicit_parts_override_the_default(): void
    {
        $signer = new RecordingSigner();
        $block = (new Signature($this->clientCertificate()))->withSigner($signer)->withParts([Part::body()]);
        $block($this->signableContext());

        $targets = $signer->lastRequest()->targets;
        static::assertCount(1, $targets);
        static::assertTrue($targets[0]->equals(self::bodyPath()));
    }

    public function test_direct_reference_embeds_a_bst_and_wires_the_key_info(): void
    {
        $signer = new RecordingSigner();
        $document = $this->signableEnvelope();
        (new Signature($this->clientCertificate(), keyRef: KeyRef::BinarySecurityToken))->withSigner($signer)($this->context($document));

        $bst = $this->only($document, self::WSSE, 'BinarySecurityToken');
        $tokenId = $bst->getAttributeNS(self::WSU, 'Id');

        $keyIdentifier = $signer->lastRequest()->keyIdentifier;
        static::assertInstanceOf(DirectReferenceKeyIdentifier::class, $keyIdentifier);

        // The strategy points the SecurityTokenReference at exactly the embedded token's id.
        $keyInfo = $keyIdentifier->apply($document, $this->clientCertificate()->publicCertificate());
        static::assertStringContainsString('#'.$tokenId, $document->stringifyNode($keyInfo));
    }

    public function test_a_certificate_path_is_advertised_as_a_pkipath_token(): void
    {
        $signer = new RecordingSigner();
        $document = $this->signableEnvelope();
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $chain = CertificateChain::fromCertificates($fixture->leafCertificate, $fixture->caCertificate);

        $block = (new Signature($this->clientCertificateFor($fixture)))
            ->withSigner($signer)
            ->withCertificatePath($chain);
        $block($this->context($document));

        $bst = $this->only($document, self::WSSE, 'BinarySecurityToken');
        static::assertSame(self::X509_PKI_PATH, $bst->getAttribute('ValueType'));
        static::assertSame(PkiPath::encode($chain), base64_decode($bst->textContent, true));

        // Both ValueTypes have to name the path: WSS4J refuses a reference whose ValueType does not match the
        // token it points at, so emitting the token alone produces a message no Java peer accepts.
        $keyIdentifier = $signer->lastRequest()->keyIdentifier;
        static::assertInstanceOf(DirectReferenceKeyIdentifier::class, $keyIdentifier);
        $keyInfo = $document->stringifyNode($keyIdentifier->apply($document, $chain->leaf()));
        static::assertStringContainsString(self::X509_PKI_PATH, $keyInfo);
        static::assertStringContainsString('#'.$bst->getAttributeNS(self::WSU, 'Id'), $keyInfo);
    }

    public function test_it_refuses_a_certificate_path_that_does_not_start_at_the_signing_certificate(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $block = new Signature($this->clientCertificate());

        // The path advertises which key verifies the signature; a leaf that is not the signing certificate
        // produces a message no peer can verify, so it is refused where it is configured.
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('signing certificate');
        $block->withCertificatePath(CertificateChain::fromCertificates($fixture->leafCertificate, $fixture->caCertificate));
    }

    public function test_it_refuses_an_empty_part_list(): void
    {
        // An empty list is not "the default": it would emit a ds:Signature covering nothing, which verifies
        // against any trusted key and protects none of the message. A list narrowed to nothing by
        // configuration must fail where it is configured rather than ship an authentic-looking envelope.
        $block = new Signature($this->clientCertificate());

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('at least one part');
        $block->withParts([]);
    }

    public function test_it_refuses_a_certificate_path_without_the_binary_security_token_reference(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $block = new Signature($this->clientCertificateFor($fixture), keyRef: KeyRef::SubjectKeyIdentifier);

        // The inline references derive their content from the certificate alone and embed no token, so there is
        // nowhere for a path to go. Silently dropping it would advertise less than the caller asked for.
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('KeyRef::BinarySecurityToken');
        $block->withCertificatePath(CertificateChain::fromCertificates($fixture->leafCertificate, $fixture->caCertificate));
    }

    public function test_subject_key_identifier_embeds_no_bst(): void
    {
        $signer = new RecordingSigner();
        $document = $this->signableEnvelope();
        (new Signature($this->clientCertificate(), keyRef: KeyRef::SubjectKeyIdentifier))->withSigner($signer)($this->context($document));

        static::assertCount(0, $this->elements($document, self::WSSE, 'BinarySecurityToken'));
        static::assertInstanceOf(X509SubjectKeyIdentifier::class, $signer->lastRequest()->keyIdentifier);
    }

    #[RequiresPhp('>= 8.4.21')]
    public function test_direct_reference_wires_the_signature_key_info_to_the_embedded_bst(): void
    {
        $certificate = $this->clientCertificate();
        $document = $this->signableEnvelope();

        (new Signature($certificate, keyRef: KeyRef::BinarySecurityToken))->withSigner($this->realSigner())($this->context($document));

        // The KeyInfo references the embedded BST by its minted id.
        $bstId = $this->only($document, self::WSSE, 'BinarySecurityToken')->getAttributeNS(self::WSU, 'Id');
        $reference = $this->only($document, self::WSSE, 'Reference');
        static::assertSame('#'.$bstId, $reference->getAttribute('URI'));
    }

    #[RequiresPhp('>= 8.4.21')]
    public function test_an_overridden_algorithm_reaches_the_signed_document(): void
    {
        $certificate = $this->clientCertificate();
        $document = $this->signableEnvelope();

        $block = (new Signature($certificate, keyRef: KeyRef::BinarySecurityToken))
            ->withSigner($this->realSigner())
            ->withSignatureMethod(SignatureMethod::RSA_SHA1)
            ->withParts([Part::body()]);
        $block($this->context($document));

        $signatureMethod = $this->only($document, self::DS, 'SignatureMethod');
        static::assertSame(SignatureMethod::RSA_SHA1->value, $signatureMethod->getAttribute('Algorithm'));
    }

    private function signableContext(): \Soap\Psr18WsseMiddleware\WSSecurity\WsseContext
    {
        return $this->context($this->signableEnvelope());
    }

    private function signableEnvelope(): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope'
            .' xmlns:soap="'.self::SOAP12.'"'
            .' xmlns:wsu="'.self::WSU.'">'
            .'<soap:Header>'
            .'<wsu:Timestamp><wsu:Created>2026-01-01T00:00:00Z</wsu:Created></wsu:Timestamp>'
            .'</soap:Header>'
            .'<soap:Body><data>x</data></soap:Body>'
            .'</soap:Envelope>'
        );
    }

    private function realSigner(): Signer
    {
        $canonicalizer = new DomCanonicalizer();

        return new Signer(
            new ReferenceCollector((new WsuIdConvention())->minter(), new TargetLocator((new WsuIdConvention())->lookup())),
            new DigestCalculator($canonicalizer, new Digest()),
            new SignedInfoBuilder(),
            $canonicalizer,
            new OpenSslSigner(),
            (new WsuIdConvention())->lookup(),
        );
    }

    /** The fixture's CA-signed leaf as a signing identity, so a path can start at the signing certificate. */
    private function clientCertificateFor(WsseSignatureFixture $fixture): ClientCertificate
    {
        return new ClientCertificate($fixture->leafCertificate->contents().$fixture->leafKey->contents());
    }

    private function clientCertificate(): ClientCertificate
    {
        $private = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        static::assertInstanceOf(OpenSSLAsymmetricKey::class, $private);

        static::assertTrue(openssl_pkey_export($private, $privatePem));
        static::assertIsString($privatePem);

        $csr = openssl_csr_new(['commonName' => 'wsse-signature-test'], $private);
        static::assertNotFalse($csr);

        // Self-sign with v3 extensions so the SubjectKeyIdentifier reference path has a value to read.
        $config = tempnam(sys_get_temp_dir(), 'wsse-x509-');
        static::assertIsString($config);
        file_put_contents($config, "[v3]\nsubjectKeyIdentifier = hash\n");

        $certificate = openssl_csr_sign($csr, null, $private, 365, [
            'config' => $config,
            'x509_extensions' => 'v3',
        ]);
        unlink($config);
        static::assertNotFalse($certificate);

        static::assertTrue(openssl_x509_export($certificate, $certificatePem));
        static::assertIsString($certificatePem);

        return new ClientCertificate($certificatePem.$privatePem);
    }
    private static function bodyPath(): Target
    {
        return Target::path(
            new QualifiedName(self::SOAP12, 'Envelope'),
            new QualifiedName(self::SOAP12, 'Body'),
        );
    }
}
