<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Encryption;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\OpenSSL\KeyTransport;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\Xml\Query;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptedKeyReader;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\DecryptionFailed;
use VeeWee\Xml\Dom\Document;

/**
 * The reader works inside the container the caller names and nowhere else. Searching the document instead would
 * make any xenc:EncryptedKey or xenc:ReferenceList in the envelope a candidate — including one an injector
 * placed in a Body or in another recipient's header — and the wrapped key would then be unwrapped with our
 * private key on the strength of the attacker's own choice of session key.
 */
final class EncryptedKeyContainerScopeTest extends TestCase
{
    private const SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const XENC = 'http://www.w3.org/2001/04/xmlenc#';

    public function test_it_reads_the_reference_list_from_the_named_container(): void
    {
        $document = $this->envelope(
            ours: '<xenc:EncryptedKey>'
                .'<xenc:CipherData><xenc:CipherValue>x</xenc:CipherValue></xenc:CipherData>'
                .'<xenc:ReferenceList><xenc:DataReference URI="#ours"/></xenc:ReferenceList>'
                .'</xenc:EncryptedKey>',
        );

        static::assertSame(['ours'], $this->reader()->dataReferences($document, $this->ours($document)));
    }

    public function test_an_encrypted_key_outside_the_container_is_not_ours(): void
    {
        // Our own header carries none, so a document-wide search would find the planted one and unwrap it.
        $document = $this->envelope(
            ours: '',
            elsewhere: '<wsse:Security><xenc:EncryptedKey>'
                .'<xenc:CipherData><xenc:CipherValue>x</xenc:CipherValue></xenc:CipherData>'
                .'<xenc:ReferenceList><xenc:DataReference URI="#attacker"/></xenc:ReferenceList>'
                .'</xenc:EncryptedKey></wsse:Security>',
        );

        $this->expectException(DecryptionFailed::class);
        $this->reader()->dataReferences($document, $this->ours($document));
    }

    public function test_a_detached_reference_list_outside_the_container_is_not_ours(): void
    {
        // The EncryptedKey is genuinely ours but names no parts; the injected list must not supply them.
        $document = $this->envelope(
            ours: '<xenc:EncryptedKey>'
                .'<xenc:CipherData><xenc:CipherValue>x</xenc:CipherValue></xenc:CipherData>'
                .'</xenc:EncryptedKey>',
            elsewhere: '<wsse:Security>'
                .'<xenc:ReferenceList><xenc:DataReference URI="#attacker"/></xenc:ReferenceList>'
                .'</wsse:Security>',
        );

        $this->expectException(DecryptionFailed::class);
        $this->reader()->dataReferences($document, $this->ours($document));
    }

    public function test_a_reference_list_in_another_recipients_header_is_not_ours(): void
    {
        $document = $this->envelope(
            ours: '<xenc:EncryptedKey>'
                .'<xenc:CipherData><xenc:CipherValue>x</xenc:CipherValue></xenc:CipherData>'
                .'</xenc:EncryptedKey>',
            otherHop: '<xenc:ReferenceList><xenc:DataReference URI="#theirs"/></xenc:ReferenceList>',
        );

        $this->expectException(DecryptionFailed::class);
        $this->reader()->dataReferences($document, $this->ours($document));
    }

    public function test_a_second_encrypted_key_in_the_container_is_still_refused(): void
    {
        // Scoping must not weaken the existing exactly-one rule inside the container.
        $key = '<xenc:EncryptedKey>'
            .'<xenc:CipherData><xenc:CipherValue>x</xenc:CipherValue></xenc:CipherData>'
            .'<xenc:ReferenceList><xenc:DataReference URI="#ours"/></xenc:ReferenceList>'
            .'</xenc:EncryptedKey>';
        $document = $this->envelope(ours: $key.$key);

        $this->expectException(DecryptionFailed::class);
        $this->reader()->dataReferences($document, $this->ours($document));
    }

    private function reader(): EncryptedKeyReader
    {
        // dataReferences() is read before any unwrap, so the key transport is never exercised here.
        return new EncryptedKeyReader(new KeyTransport());
    }

    /**
     * The Security header addressed to the ultimate receiver — the one the WS-Security blocks would pass in.
     */
    private function ours(Document $document): Element
    {
        return Query::elements(
            $document,
            '/soap:Envelope/soap:Header/'.Namespaces::Wsse->qualify('Security').'[not(@soap:role)]',
        )->expectSingle();
    }

    private function envelope(string $ours, string $elsewhere = '', string $otherHop = ''): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP.'"'
            .' xmlns:wsse="'.self::WSSE.'" xmlns:xenc="'.self::XENC.'">'
            .'<soap:Header>'
            .'<wsse:Security>'.$ours.'</wsse:Security>'
            .'<wsse:Security soap:role="urn:other-hop">'.$otherHop.'</wsse:Security>'
            .'</soap:Header>'
            .'<soap:Body wsu:Id="ours" xmlns:wsu="urn:wsu">'.$elsewhere.'</soap:Body>'
            .'</soap:Envelope>'
        );
    }
}
