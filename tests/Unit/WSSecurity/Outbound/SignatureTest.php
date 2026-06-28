<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound;

use DOMDocument;
use Exception;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\RequiresPhp;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\OpenSSL\Signer as OpenSslSigner;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy\DirectReferenceKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy\X509SubjectKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyRef;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Signature;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Manipulator\WsuIdMinter;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Canonicalization\DomCanonicalizer;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\PartLocator;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Signing\DigestCalculator;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Signing\KeyInfoBuilder;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Signing\ReferenceCollector;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Signing\SignedInfoBuilder;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Signing\Signer;
use VeeWee\Xml\Dom\Document;

#[RequiresPhp('>= 8.4.21')]
final class SignatureTest extends OutboundTestCase
{
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';

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
        $profile = new SecurityProfile(signatureMethod: SignatureMethod::RSA_SHA512);
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

    public function test_with_methods_are_immutable(): void
    {
        $original = (new Signature($this->clientCertificate()))->withSigner(new RecordingSigner());

        static::assertNotSame($original, $original->withSignatureMethod(SignatureMethod::RSA_SHA1));
        static::assertNotSame($original, $original->withDigestMethod(DigestMethod::SHA512));
        static::assertNotSame($original, $original->withCanonicalization(SignatureCanonicalization::EXC_C14N_COMMENTS));
        static::assertNotSame($original, $original->withParts([Part::body()]));
    }

    public function test_with_signer_routes_signing_to_the_given_signer(): void
    {
        $signer = new RecordingSigner();
        (new Signature($this->clientCertificate()))->withSigner($signer)($this->signableContext());

        // lastRequest() throws unless sign() ran on the injected double, proving the override is used.
        static::assertInstanceOf(SignatureMethod::class, $signer->lastRequest()->signatureMethod);
    }

    public function test_default_parts_are_body_and_timestamp(): void
    {
        $signer = new RecordingSigner();
        (new Signature($this->clientCertificate()))->withSigner($signer)($this->signableContext());

        $parts = $signer->lastRequest()->parts;
        static::assertCount(2, $parts);
        static::assertTrue($parts[0]->equals(Part::body()));
        static::assertTrue($parts[1]->equals(Part::timestamp()));
    }

    public function test_explicit_parts_override_the_default(): void
    {
        $signer = new RecordingSigner();
        $block = (new Signature($this->clientCertificate()))->withSigner($signer)->withParts([Part::body()]);
        $block($this->signableContext());

        $parts = $signer->lastRequest()->parts;
        static::assertCount(1, $parts);
        static::assertTrue($parts[0]->equals(Part::body()));
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

    public function test_subject_key_identifier_embeds_no_bst(): void
    {
        $signer = new RecordingSigner();
        $document = $this->signableEnvelope();
        (new Signature($this->clientCertificate(), keyRef: KeyRef::SubjectKeyIdentifier))->withSigner($signer)($this->context($document));

        static::assertCount(0, $this->elements($document, self::WSSE, 'BinarySecurityToken'));
        static::assertInstanceOf(X509SubjectKeyIdentifier::class, $signer->lastRequest()->keyIdentifier);
    }

    public function test_direct_reference_round_trips_under_xmlseclibs(): void
    {
        $certificate = $this->clientCertificate();
        $document = $this->signableEnvelope();

        (new Signature($certificate, keyRef: KeyRef::BinarySecurityToken))->withSigner($this->realSigner())($this->context($document));

        // The KeyInfo references the embedded BST by its minted id.
        $bstId = $this->only($document, self::WSSE, 'BinarySecurityToken')->getAttributeNS(self::WSU, 'Id');
        $reference = $this->only($document, self::WSSE, 'Reference');
        static::assertSame('#'.$bstId, $reference->getAttribute('URI'));

        // The produced signature verifies under an independent implementation.
        static::assertTrue($this->verifiesWithXmlSecLibs($document, $certificate->publicCertificate()->contents()));
    }

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
            new ReferenceCollector(new WsuIdMinter(), new PartLocator()),
            new DigestCalculator($canonicalizer, new Digest()),
            new SignedInfoBuilder(),
            new KeyInfoBuilder(),
            $canonicalizer,
            new OpenSslSigner(),
        );
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

    private function verifiesWithXmlSecLibs(Document $document, string $certificatePem): bool
    {
        $dom = new DOMDocument();
        static::assertTrue($dom->loadXML($document->toXmlString()));

        $dsig = new XMLSecurityDSig();
        $dsig->idKeys = ['wsu:Id'];
        $dsig->idNS = ['wsu' => self::WSU];

        $signatureNode = $dsig->locateSignature($dom);
        static::assertNotNull($signatureNode);

        $dsig->canonicalizeSignedInfo();

        try {
            if (!$dsig->validateReference()) {
                return false;
            }
        } catch (Exception) {
            return false;
        }

        $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'public']);
        $key->loadKey($certificatePem, false, true);

        return $dsig->verify($key) === 1;
    }
}
