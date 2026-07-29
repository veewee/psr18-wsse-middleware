<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Inbound;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\Decrypt;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use VeeWee\Xml\Dom\Document;

/**
 * The session key is unwrapped with our private key, so which xenc:EncryptedKey counts as ours decides what we
 * apply it to. Our public key is public: anyone can wrap a key to us, so an EncryptedKey found anywhere in the
 * envelope is not evidence the sender meant it for this receiver. The block therefore reads it out of the
 * Security header addressed to us (the same scope the signature verifier uses), and a message carrying no
 * header for us is refused rather than decrypted against whatever else the envelope holds.
 */
final class DecryptScopeTest extends TestCase
{
    private const SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';

    public function test_it_scopes_decryption_to_the_security_header_addressed_to_us(): void
    {
        $context = $this->context(
            '<soap:Header><wsse:Security><ours/></wsse:Security></soap:Header>',
            new SecurityProfile(),
        );
        $decryptor = new RecordingDecryptor();

        (new Decrypt($this->privateKey()))->withDecryptor($decryptor)($context);

        static::assertSame('ours', $decryptor->lastRequest()?->container->firstElementChild?->localName);
    }

    public function test_a_profile_naming_an_actor_decrypts_within_that_actors_header(): void
    {
        // Configured as a named intermediary, the header carrying our actor is the one we read the wrapped key
        // from. The untargeted header belongs to the ultimate receiver and its key is not ours to unwrap.
        $context = $this->context(
            '<soap:Header>'
            .'<wsse:Security><ultimate/></wsse:Security>'
            .'<wsse:Security soap:role="urn:ours"><ours/></wsse:Security>'
            .'</soap:Header>',
            new SecurityProfile(actorOrRole: 'urn:ours'),
        );
        $decryptor = new RecordingDecryptor();

        (new Decrypt($this->privateKey()))->withDecryptor($decryptor)($context);

        static::assertSame('ours', $decryptor->lastRequest()?->container->firstElementChild?->localName);
    }

    public function test_a_security_header_addressed_to_another_hop_is_not_ours_to_decrypt(): void
    {
        // The header exists but names an intermediary, so the key inside it was wrapped for that hop.
        $context = $this->context(
            '<soap:Header><wsse:Security soap:role="urn:some-intermediary"/></soap:Header>',
            new SecurityProfile(),
        );

        $this->expectException(SecurityFault::class);
        (new Decrypt($this->privateKey()))->withDecryptor(new RecordingDecryptor())($context);
    }

    public function test_a_security_header_planted_in_the_body_is_not_a_candidate(): void
    {
        // The attack this closes: an injector cannot reach our private key by planting a Security header of
        // their own, because only a soap:Header child addressed to us is looked at.
        $context = $this->context(
            '<soap:Header/>',
            new SecurityProfile(),
            '<soap:Body><wsse:Security><planted/></wsse:Security></soap:Body>',
        );

        $this->expectException(SecurityFault::class);
        (new Decrypt($this->privateKey()))->withDecryptor(new RecordingDecryptor())($context);
    }

    public function test_a_message_carrying_no_security_header_is_refused(): void
    {
        $context = $this->context('', new SecurityProfile());

        $this->expectException(SecurityFault::class);
        (new Decrypt($this->privateKey()))->withDecryptor(new RecordingDecryptor())($context);
    }

    private function context(
        string $header,
        SecurityProfile $profile,
        string $body = '<soap:Body/>',
    ): WsseContext {
        return new WsseContext(
            Document::fromXmlString(
                '<soap:Envelope xmlns:soap="'.self::SOAP.'" xmlns:wsse="'.self::WSSE.'">'
                .$header.$body.'</soap:Envelope>'
            ),
            SoapVersion::Soap12,
            $profile,
        );
    }

    private function privateKey(): Key
    {
        return new Key('not-real-pem-material');
    }
}
