<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Inbound;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\DecryptionFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\Decrypt;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Key;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\KeyHandle;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\DecryptionRequest;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\XmlDecryptor;
use VeeWee\Xml\Dom\Document;

/**
 * The Decrypt block wires the inbound document and recipient private key to the XmlDecryptor SPI and
 * collapses every decryption failure to one uniform SecurityFault. These tests inject a recording or
 * throwing fake decryptor; the real-crypto round-trip lives in DecryptRoundTripTest.
 */
final class DecryptTest extends TestCase
{
    public function test_it_delegates_the_context_document_to_the_decryptor(): void
    {
        $decryptor = new RecordingDecryptor();
        $context = $this->context();

        (new Decrypt($this->privateKey(), $decryptor))($context);

        static::assertSame($context->document(), $decryptor->lastDocument());
    }

    public function test_it_passes_the_constructed_private_key_handle(): void
    {
        $decryptor = new RecordingDecryptor();
        $handle = $this->privateKey();

        (new Decrypt($handle, $decryptor))($this->context());

        static::assertInstanceOf(DecryptionRequest::class, $decryptor->lastRequest());
        static::assertSame($handle, $decryptor->lastRequest()->privateKey);
    }

    public function test_it_returns_silently_on_success(): void
    {
        $decryptor = new RecordingDecryptor();

        $this->expectNotToPerformAssertions();
        (new Decrypt($this->privateKey(), $decryptor))($this->context());
    }

    public function test_it_maps_a_decryption_failure_to_a_security_fault(): void
    {
        $decryptor = new ThrowingDecryptor(DecryptionFailed::withReason('any reason at all'));

        $this->expectException(SecurityFault::class);
        (new Decrypt($this->privateKey(), $decryptor))($this->context());
    }

    public function test_the_security_fault_carries_no_decryption_detail(): void
    {
        $reason = 'OAEP digest is not SHA-1';
        $decryptor = new ThrowingDecryptor(DecryptionFailed::withReason($reason));

        try {
            (new Decrypt($this->privateKey(), $decryptor))($this->context());
            static::fail('Expected a SecurityFault.');
        } catch (SecurityFault $fault) {
            static::assertStringNotContainsString($reason, $fault->getMessage());
        }
    }

    public function test_the_security_fault_chains_the_original_cause_for_operator_logs(): void
    {
        $cause = DecryptionFailed::withReason('any reason at all');
        $decryptor = new ThrowingDecryptor($cause);

        try {
            (new Decrypt($this->privateKey(), $decryptor))($this->context());
            static::fail('Expected a SecurityFault.');
        } catch (SecurityFault $fault) {
            static::assertSame($cause, $fault->getPrevious());
        }
    }

    public function test_it_does_not_rewrap_other_exceptions(): void
    {
        $unexpected = new RuntimeException('a programming error, not part of the SPI contract');
        $decryptor = new ThrowingDecryptor($unexpected);

        $this->expectExceptionObject($unexpected);
        (new Decrypt($this->privateKey(), $decryptor))($this->context());
    }

    private function context(): WsseContext
    {
        return new WsseContext(
            Document::fromXmlString('<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Body/></soap:Envelope>'),
            SoapVersion::Soap12,
            new SecurityProfile(),
        );
    }

    private function privateKey(): KeyHandle
    {
        return KeyHandle::for(new Key('not-real-pem-material'));
    }
}
