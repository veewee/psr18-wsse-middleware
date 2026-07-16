<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound;

use Dom\Element;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\RequiresPhp;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\OpenSSL\Signer as OpenSslSigner;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\VerifySignature;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\KeyRef;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Signature;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Timestamp;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator\WsuIdLookup;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Manipulator\WsuIdMinter;
use Soap\Psr18WsseMiddleware\Xml\Locator\WsuId;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\DomCanonicalizer;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\DigestCalculator;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\KeyInfoBuilder;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\ReferenceCollector;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\SignedInfoBuilder;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\Signer;
use Soap\Psr18WsseMiddleware\XmlSecurity\TargetLocator;
use VeeWee\Xml\Dom\Document;

/**
 * Proves an inclusive Canonical XML 1.0 signature produced by the real outbound blocks over a freshly
 * minted Timestamp and Security header is reproducible from the wire. The Timestamp and Security header are
 * built with element-namespace declarations that the live DOM omits but the serialized wire materialises, so
 * inclusive C14N (which folds in-scope declarations into the digest) is the path where a signer that digests
 * the live DOM disagrees with any verifier reading the wire. The signer must digest exactly what goes on the
 * wire for the self-verification to hold across libxml versions.
 */
#[RequiresPhp('>= 8.4.21')]
final class InclusiveC14nSelfConsistencyTest extends OutboundTestCase
{
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';

    public function test_the_engine_verifier_accepts_its_own_inclusive_c14n_signature(): void
    {
        $certificate = $this->clientCertificate();
        $document = $this->bareEnvelope();
        $context = $this->context(
            $document,
            new SecurityProfile(crypto: new CryptoPolicy(canonicalization: SignatureCanonicalization::C14N)),
        );

        (new Timestamp())($context);
        (new Signature($certificate, keyRef: KeyRef::BinarySecurityToken))
            ->withSigner($this->realSigner())($context);

        (new VerifySignature(
            TrustStore::fromCertificates(new Certificate($certificate->publicCertificate()->contents())),
            signed: [Part::body(), Part::timestamp()],
        ))($this->context(
            // The verifier reads the wire: a fresh parse of the serialized document, never the signer's DOM.
            $this->wire($document),
            new SecurityProfile(crypto: new CryptoPolicy(acceptedCanonicalizations: [
                SignatureCanonicalization::C14N,
                SignatureCanonicalization::EXC_C14N,
            ])),
        ));

        // A SecurityFault would have escaped above; reaching here proves the wire verified.
        $this->addToAssertionCount(1);
    }

    public function test_each_reference_digest_matches_a_recomputation_from_the_wire(): void
    {
        $certificate = $this->clientCertificate();
        $document = $this->bareEnvelope();
        $context = $this->context(
            $document,
            new SecurityProfile(crypto: new CryptoPolicy(canonicalization: SignatureCanonicalization::C14N)),
        );

        (new Timestamp())($context);
        (new Signature($certificate, keyRef: KeyRef::BinarySecurityToken))
            ->withSigner($this->realSigner())($context);

        // The DigestValue the signer emitted must equal what a verifier recomputes from the wire. The signer
        // digests the live DOM; the wire materialises namespace declarations the live DOM omits, so under
        // inclusive C14N these only match when the signer digested the wire.
        $wire = $this->wire($document);
        $canonicalizer = new DomCanonicalizer();
        $digest = new Digest();

        foreach ($this->referenceDigests($wire) as $wsuId => $emitted) {
            $element = WsuId::resolve($wire, $wsuId);
            $recomputed = base64_encode($digest->hash(
                $canonicalizer->canonicalize($element, SignatureCanonicalization::C14N),
                DigestMethod::SHA256,
            ));

            static::assertSame($emitted, $recomputed, 'Reference '.$wsuId.' digest does not match the wire');
        }
    }

    /**
     * @return array<non-empty-string, string> wsu:Id (without the '#' prefix) to its emitted base64 DigestValue
     */
    private function referenceDigests(Document $wire): array
    {
        $digests = [];
        foreach ($wire->toUnsafeDocument()->getElementsByTagNameNS(self::DS, 'Reference') as $reference) {
            static::assertInstanceOf(Element::class, $reference);
            $uri = ltrim($reference->getAttribute('URI'), '#');
            static::assertNotSame('', $uri);

            $digestValue = $reference->getElementsByTagNameNS(self::DS, 'DigestValue')->item(0);
            static::assertInstanceOf(Element::class, $digestValue);

            $digests[$uri] = $digestValue->textContent;
        }

        static::assertNotEmpty($digests);

        return $digests;
    }

    private function wire(Document $document): Document
    {
        return Document::fromXmlString($document->toXmlString());
    }

    /**
     * A SOAP 1.2 envelope that does not predeclare the wsu or wsse prefixes, so the elements the engine mints
     * carry namespace declarations the live DOM and the serialized wire materialise differently.
     */
    private function bareEnvelope(): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'">'
            .'<soap:Header/><soap:Body><data>x</data></soap:Body>'
            .'</soap:Envelope>'
        );
    }

    private function realSigner(): Signer
    {
        $canonicalizer = new DomCanonicalizer();

        return new Signer(
            new ReferenceCollector(new WsuIdMinter(), new TargetLocator(new WsuIdLookup())),
            new DigestCalculator($canonicalizer, new Digest()),
            new SignedInfoBuilder(),
            new KeyInfoBuilder(),
            $canonicalizer,
            new OpenSslSigner(),
            new WsuIdLookup(),
        );
    }

    private function clientCertificate(): ClientCertificate
    {
        $private = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        static::assertInstanceOf(OpenSSLAsymmetricKey::class, $private);

        static::assertTrue(openssl_pkey_export($private, $privatePem));
        static::assertIsString($privatePem);

        $csr = openssl_csr_new(['commonName' => 'wsse-inclusive-c14n-test'], $private);
        static::assertNotFalse($csr);

        $certificate = openssl_csr_sign($csr, null, $private, 365, ['digest_alg' => 'sha256']);
        static::assertNotFalse($certificate);

        static::assertTrue(openssl_x509_export($certificate, $certificatePem));
        static::assertIsString($certificatePem);

        return new ClientCertificate($certificatePem.$privatePem);
    }
}
