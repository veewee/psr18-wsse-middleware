<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Encryption;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\OpenSSL\KeyTransport;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptedKeyReader;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\DecryptionFailed;
use VeeWee\Xml\Dom\Document;

/**
 * XML-Enc allows the xenc:ReferenceList naming the encrypted parts to sit inside the xenc:EncryptedKey or to
 * stand detached beside it in the Security header; peers emit both. The reader accepts either, but never both
 * at once and never two of one: which parts a message claims to have encrypted decides what the decryptor
 * touches, so a second list must be an outright refusal rather than a candidate to choose from.
 */
final class EncryptedKeyReferenceListTest extends TestCase
{
    private const SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const XENC = 'http://www.w3.org/2001/04/xmlenc#';

    public function test_it_reads_a_reference_list_carried_inside_the_encrypted_key(): void
    {
        $document = $this->envelope(
            inside: '<xenc:ReferenceList><xenc:DataReference URI="#body"/></xenc:ReferenceList>',
        );

        static::assertSame(['body'], $this->reader()->dataReferences($document));
    }

    public function test_it_reads_a_detached_reference_list_beside_the_encrypted_key(): void
    {
        $document = $this->envelope(
            detached: '<xenc:ReferenceList><xenc:DataReference URI="#body"/><xenc:DataReference URI="#ts"/></xenc:ReferenceList>',
        );

        static::assertSame(['body', 'ts'], $this->reader()->dataReferences($document));
    }

    public function test_it_refuses_a_message_carrying_both_forms(): void
    {
        // Nothing tells us which list the sender meant, and picking one would let the other be injected.
        $document = $this->envelope(
            inside: '<xenc:ReferenceList><xenc:DataReference URI="#body"/></xenc:ReferenceList>',
            detached: '<xenc:ReferenceList><xenc:DataReference URI="#attacker"/></xenc:ReferenceList>',
        );

        $this->expectException(DecryptionFailed::class);
        $this->reader()->dataReferences($document);
    }

    public function test_it_refuses_a_duplicated_detached_reference_list(): void
    {
        $document = $this->envelope(
            detached: '<xenc:ReferenceList><xenc:DataReference URI="#body"/></xenc:ReferenceList>'
                .'<xenc:ReferenceList><xenc:DataReference URI="#attacker"/></xenc:ReferenceList>',
        );

        $this->expectException(DecryptionFailed::class);
        $this->reader()->dataReferences($document);
    }

    public function test_a_duplicated_inner_list_is_refused_rather_than_falling_through_to_a_detached_one(): void
    {
        // The dangerous shape: if a duplicated inner list read as "absent", an injected detached list would
        // silently become the one that decides which parts get decrypted.
        $document = $this->envelope(
            inside: '<xenc:ReferenceList><xenc:DataReference URI="#body"/></xenc:ReferenceList>'
                .'<xenc:ReferenceList><xenc:DataReference URI="#body"/></xenc:ReferenceList>',
            detached: '<xenc:ReferenceList><xenc:DataReference URI="#attacker"/></xenc:ReferenceList>',
        );

        $this->expectException(DecryptionFailed::class);
        $this->reader()->dataReferences($document);
    }

    public function test_it_refuses_a_message_carrying_no_reference_list_at_all(): void
    {
        $document = $this->envelope();

        $this->expectException(DecryptionFailed::class);
        $this->reader()->dataReferences($document);
    }

    public function test_it_refuses_a_reference_list_declaring_no_references(): void
    {
        $document = $this->envelope(detached: '<xenc:ReferenceList/>');

        $this->expectException(DecryptionFailed::class);
        $this->reader()->dataReferences($document);
    }

    private function reader(): EncryptedKeyReader
    {
        // dataReferences() is read before any unwrap, so the key transport is never exercised here.
        return new EncryptedKeyReader(new KeyTransport());
    }

    private function envelope(string $inside = '', string $detached = ''): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP.'"'
            .' xmlns:wsse="'.self::WSSE.'" xmlns:xenc="'.self::XENC.'">'
            .'<soap:Header><wsse:Security>'
            .'<xenc:EncryptedKey>'
            .'<xenc:CipherData><xenc:CipherValue>x</xenc:CipherValue></xenc:CipherData>'
            .$inside
            .'</xenc:EncryptedKey>'
            .$detached
            .'</wsse:Security></soap:Header><soap:Body wsu:Id="body" xmlns:wsu="urn:wsu"/></soap:Envelope>'
        );
    }
}
