<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Inbound;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Psl\DateTime\Timestamp;
use Psl\DateTime\Timezone;
use RuntimeException;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\DistinguishedName;
use Soap\Psr18WsseMiddleware\KeyStore\TrustedSigner;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\Decrypt;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\ValidateTimestamp;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\VerifySignature;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\DecryptionFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdLookup;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\CertificateReference;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\KeyInfoResolver;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\VerifiedReferences;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\VerifiedSignature;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\Verifier;
use SoapTest\Psr18WsseMiddleware\Unit\Clock\FrozenClock;
use VeeWee\Xml\Dom\Document;

/**
 * The cross-block half of the no-oracle guarantee. Each block's own suite proves its failures collapse to a
 * SecurityFault; this suite proves the faults are indistinguishable BETWEEN blocks: same type, same code,
 * byte-identical message: so a peer cannot tell a decryption failure from a signature failure from a stale
 * timestamp, and cannot learn which detail text triggered any of them.
 */
final class FaultUniformityTest extends TestCase
{
    private const SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';

    private const DETAIL_TEXTS = ['sig-detail-text', 'decrypt-detail-text', 'keyinfo-detail-text'];

    public function test_every_inbound_block_fails_with_one_indistinguishable_fault(): void
    {
        $faults = [
            'stale timestamp' => $this->faultFrom($this->staleTimestamp(...)),
            'signature verification failure' => $this->faultFrom($this->signatureFailure(...)),
            'missing required signed part' => $this->faultFrom($this->missingRequiredPart(...)),
            'decryption failure' => $this->faultFrom($this->decryptionFailure(...)),
            'no security header for this receiver' => $this->faultFrom($this->noSecurityHeader(...)),
            'a key-info resolver raising its own type' => $this->faultFrom($this->keyInfoResolverFailure(...)),
        ];

        $reference = $faults['stale timestamp'];
        foreach ($faults as $origin => $fault) {
            static::assertSame(SecurityFault::class, $fault::class, $origin);
            static::assertSame($reference->getMessage(), $fault->getMessage(), $origin);
            static::assertSame($reference->getCode(), $fault->getCode(), $origin);

            foreach (self::DETAIL_TEXTS as $detail) {
                static::assertStringNotContainsString($detail, $fault->getMessage(), $origin);
            }
        }
    }

    /**
     * @param callable(): void $trigger
     */
    private function faultFrom(callable $trigger): SecurityFault
    {
        try {
            $trigger();
        } catch (SecurityFault $fault) {
            return $fault;
        }

        static::fail('Expected a SecurityFault.');
    }

    private function staleTimestamp(): void
    {
        $xml = '<soap:Envelope xmlns:soap="'.self::SOAP.'"><soap:Header>'
            .'<wsse:Security xmlns:wsse="'.self::WSSE.'">'
            .'<wsu:Timestamp xmlns:wsu="'.self::WSU.'">'
            .'<wsu:Created>2026-01-01T00:00:00Z</wsu:Created>'
            .'<wsu:Expires>2026-01-01T00:05:00Z</wsu:Expires>'
            .'</wsu:Timestamp>'
            .'</wsse:Security>'
            .'</soap:Header><soap:Body><data>x</data></soap:Body></soap:Envelope>';
        $now = Timestamp::parse('2026-01-01T12:00:00Z', "yyyy-MM-dd'T'HH:mm:ss'Z'", Timezone::UTC);

        ((new ValidateTimestamp())->withClock(new FrozenClock($now)))($this->context($xml));
    }

    /**
     * The key-info resolver is a replaceable seam, so an implementation can raise a type of its own. It must reach
     * a peer as the same fault as everything else: a distinguishable one would say which shape of ds:KeyInfo the
     * message failed on, and it is reachable by anyone who can send a message.
     */
    private function keyInfoResolverFailure(): void
    {
        $hostile = new class implements KeyInfoResolver {
            public function read(Document $document, Element $signatureElement, IdLookup $idLookup): CertificateReference
            {
                throw new RuntimeException(self::DETAIL);
            }

            private const DETAIL = 'keyinfo-detail-text';
        };

        (new VerifySignature($this->trustStore(), signed: [Part::body()]))
            ->withVerifier(Verifier::create((new WsuIdConvention())->lookup(), $hostile))($this->context());
    }

    private function signatureFailure(): void
    {
        (new VerifySignature($this->trustStore(), signed: [Part::body()]))
            ->withVerifier(new ThrowingVerifier(SignatureVerificationFailed::withReason(self::DETAIL_TEXTS[0])))($this->context());
    }

    private function missingRequiredPart(): void
    {
        // The verifier succeeds but reports an empty signed set, so the required Body is not covered.
        $verified = new VerifiedSignature(
            new VerifiedReferences([]),
            new TrustedSigner(DistinguishedName::fromString('CN=test'), new Certificate('pem')),
        );

        (new VerifySignature($this->trustStore(), signed: [Part::body()]))
            ->withVerifier(new RecordingVerifier($verified))($this->context());
    }

    private function decryptionFailure(): void
    {
        (new Decrypt(new Key('not-real-pem-material')))
            ->withDecryptor(new ThrowingDecryptor(DecryptionFailed::withReason(self::DETAIL_TEXTS[1])))($this->context());
    }

    /**
     * The default envelope carries a Security header addressed to the ultimate receiver. Without one, the
     * signature and decryption blocks refuse on the missing header and never consult the injected fake, which
     * would make the detail-text assertions above vacuous: they would be checking a fault the fake never
     * caused. The blocks that read a header must be given one for their real failure to be the trigger.
     */
    /**
     * A response addressed to nobody we are is refused, and must be refused with the same fault as a wrong key:
     * telling the two apart would say whether the recipient was expected to decrypt at all.
     */
    private function noSecurityHeader(): void
    {
        $xml = '<soap:Envelope xmlns:soap="'.self::SOAP.'"><soap:Body><data>x</data></soap:Body></soap:Envelope>';

        (new Decrypt(new Key('not-real-pem-material')))
            ->withDecryptor(new ThrowingDecryptor(DecryptionFailed::withReason(self::DETAIL_TEXTS[1])))($this->context($xml));
    }

    private function context(?string $xml = null): WsseContext
    {
        return new WsseContext(
            Document::fromXmlString($xml ?? '<soap:Envelope xmlns:soap="'.self::SOAP.'">'
                .'<soap:Header><wsse:Security xmlns:wsse="'.self::WSSE.'"/></soap:Header>'
                .'<soap:Body><data>x</data></soap:Body></soap:Envelope>'),
            SoapVersion::Soap12,
            new SecurityProfile(),
        );
    }

    private function trustStore(): TrustStore
    {
        return TrustStore::fromCertificates(new Certificate('anchor-pem'));
    }
}
