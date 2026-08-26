<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound;

use OpenSSLAsymmetricKey;
use Soap\Psr18WsseMiddleware\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\KeyRef;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Signature;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\Xml\QualifiedName;
use Soap\Psr18WsseMiddleware\XmlSecurity\Target;
use Soap\Psr18WsseMiddleware\XmlSecurity\TargetKind;
use VeeWee\Xml\Dom\Document;

/**
 * Covers how the Signature block lowers Parts to engine Targets: the target-resolution step only, driven by a
 * recording signer so it never canonicalizes. This is why it is not gated on the libxml C14N floor the
 * real-crypto SignatureTest carries: no signing happens here.
 */
final class SignatureTargetResolutionTest extends OutboundTestCase
{
    public function test_security_header_contents_expands_to_every_child_of_the_security_header(): void
    {
        $signer = new RecordingSigner();
        $document = $this->envelopeWithSecurityHeader('<wsu:Timestamp xmlns:wsu="'.self::WSU.'"/>');

        (new Signature($this->clientCertificate(), keyRef: KeyRef::SubjectKeyIdentifier))
            ->withSigner($signer)
            ->withParts([Part::securityHeaderContents()])($this->context($document));

        $targets = $signer->lastRequest()->targets;
        static::assertCount(1, $targets);
        static::assertSame(TargetKind::Id, $targets[0]->kind());
        // The expansion stamped a wsu:Id on the timestamp and targeted it by that id.
        $timestamp = $this->only($document, self::WSU, 'Timestamp');
        static::assertSame($targets[0]->id(), $timestamp->getAttributeNS(self::WSU, 'Id'));
    }

    public function test_soap_headers_expands_to_header_blocks_except_the_security_header(): void
    {
        $signer = new RecordingSigner();
        $document = $this->envelopeWithSecurityHeader('', '<wsa:To xmlns:wsa="urn:wsa">urn:svc</wsa:To>');

        (new Signature($this->clientCertificate(), keyRef: KeyRef::SubjectKeyIdentifier))
            ->withSigner($signer)
            ->withParts([Part::soapHeaders()])($this->context($document));

        $targets = $signer->lastRequest()->targets;
        static::assertCount(1, $targets, 'Only the wsa:To header is signed; the Security header is excluded.');
        $to = $this->only($document, 'urn:wsa', 'To');
        static::assertSame($targets[0]->id(), $to->getAttributeNS(self::WSU, 'Id'));
    }

    public function test_the_default_parts_are_the_body_and_the_security_header_contents(): void
    {
        $signer = new RecordingSigner();
        $document = $this->envelopeWithSecurityHeader('<wsu:Timestamp xmlns:wsu="'.self::WSU.'"/>');

        // Default keyRef embeds a BinarySecurityToken, so the Security header carries the timestamp + the BST.
        (new Signature($this->clientCertificate()))->withSigner($signer)($this->context($document));

        $targets = $signer->lastRequest()->targets;
        static::assertTrue($targets[0]->equals(self::bodyPath()), 'Body is signed first.');
        static::assertGreaterThanOrEqual(2, count($targets), 'Body plus the security-header children are signed.');
        foreach (array_slice($targets, 1) as $target) {
            static::assertSame(TargetKind::Id, $target->kind());
        }
    }

    public function test_it_never_fails_when_the_security_header_is_empty_but_the_body_is_still_signed(): void
    {
        $signer = new RecordingSigner();
        $document = $this->envelopeWithSecurityHeader('');

        (new Signature($this->clientCertificate(), keyRef: KeyRef::SubjectKeyIdentifier))
            ->withSigner($signer)($this->context($document));

        // No timestamp, SKI reference embeds no token: securityHeaderContents adds nothing, Body still signs.
        $targets = $signer->lastRequest()->targets;
        static::assertCount(1, $targets);
        static::assertTrue($targets[0]->equals(self::bodyPath()));
    }

    public function test_it_throws_when_only_dynamic_parts_match_nothing(): void
    {
        $signer = new RecordingSigner();
        $document = $this->envelopeWithSecurityHeader('');

        $this->expectException(WsseHeaderException::class);
        (new Signature($this->clientCertificate(), keyRef: KeyRef::SubjectKeyIdentifier))
            ->withSigner($signer)
            ->withParts([Part::securityHeaderContents()])($this->context($document));
    }

    private function envelopeWithSecurityHeader(string $securityChildren, string $otherHeaders = ''): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'" xmlns:wsse="'.self::WSSE.'">'
            .'<soap:Header>'.$otherHeaders.'<wsse:Security>'.$securityChildren.'</wsse:Security></soap:Header>'
            .'<soap:Body><data>x</data></soap:Body>'
            .'</soap:Envelope>'
        );
    }

    private function clientCertificate(): ClientCertificate
    {
        $private = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        static::assertInstanceOf(OpenSSLAsymmetricKey::class, $private);
        static::assertTrue(openssl_pkey_export($private, $privatePem));
        static::assertIsString($privatePem);

        $csr = openssl_csr_new(['commonName' => 'wsse-target-resolution-test'], $private);
        static::assertNotFalse($csr);

        $config = tempnam(sys_get_temp_dir(), 'wsse-x509-');
        static::assertIsString($config);
        file_put_contents($config, "[v3]\nsubjectKeyIdentifier = hash\n");

        $certificate = openssl_csr_sign($csr, null, $private, 365, ['config' => $config, 'x509_extensions' => 'v3']);
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
