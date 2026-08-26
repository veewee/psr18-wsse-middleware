<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Inbound;

use Dom\Element;
use Phpro\ResourceStream\Factory\MemoryStream;
use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use Soap\Psr18AttachmentsMiddleware\Attachment\Attachment;
use Soap\Psr18AttachmentsMiddleware\Storage\AttachmentStorage;
use Soap\Psr18AttachmentsMiddleware\Storage\AttachmentStorageInterface;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\AttachmentParts;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\Decrypt;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\ResolveOptimizedBytes;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\ExchangeKeys;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\WrappedSessionKey;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Encryption;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartCoverage;
use SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\WsseSignatureFixture;
use VeeWee\Xml\Dom\Document;

/**
 * The end-to-end proof that a message from a peer which moved its cipher bytes into MIME parts decrypts.
 *
 * The optimized message is built by taking a genuinely encrypted one and doing to it exactly what the peer
 * does: base64-decode each cipher value, put those raw bytes in a part of its own, and leave an xop:Include
 * behind. So the ciphertext is real, the framing is real, and only the packaging is simulated. The interop
 * suite runs the same shapes against a live WSS4J peer, which is what settles the packaging itself.
 *
 * Both values are optimized here at once, which is more than any single peer does in one message: .NET and
 * CXF switch on a size threshold, so a small wrapped key normally stays inline. Doing both proves the reader
 * treats each value on its own.
 */
#[RequiresPhp('>= 8.4.21')]
final class DecryptOptimizedBytesRoundTripTest extends TestCase
{
    private const XENC = 'http://www.w3.org/2001/04/xmlenc#';
    private const XOP = 'http://www.w3.org/2004/08/xop/include';
    private const PLAINTEXT = 'the body a peer sent us';

    public function test_it_decrypts_a_message_whose_cipher_bytes_travelled_in_mime_parts(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $this->encrypted($fixture);
        $storage = new AttachmentStorage();

        $moved = $this->optimize($document, $storage);
        static::assertSame(2, $moved, 'both the wrapped key and the body cipher value should have moved');

        $this->resolve($document, $storage);
        $this->decrypt($fixture, $document);

        static::assertStringContainsString(self::PLAINTEXT, $document->toXmlString());
    }

    public function test_without_the_block_the_same_message_is_refused(): void
    {
        // The behaviour this feature exists to change: fail-closed, and silent about why.
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $this->encrypted($fixture);

        $this->optimize($document, new AttachmentStorage());

        $this->expectException(SecurityFault::class);
        $this->decrypt($fixture, $document);
    }

    private function encrypted(WsseSignatureFixture $fixture): Document
    {
        $document = $fixture->envelope(body: '<data>'.self::PLAINTEXT.'</data>');

        (new Encryption(new WrappedSessionKey($fixture->leafCertificate)))(
            new WsseContext($document, SoapVersion::Soap12, $this->profile(), new ExchangeKeys()),
        );

        return $document;
    }

    /**
     * Does to the document what a peer with MTOM enabled does on its way out.
     *
     * @return int the number of values moved into parts
     */
    private function optimize(Document $document, AttachmentStorageInterface $storage): int
    {
        $moved = 0;
        foreach ($this->cipherValues($document) as $index => $cipherValue) {
            $cid = 'cipher-'.$index.'@example.com';
            $bytes = base64_decode(trim($cipherValue->textContent), true);
            static::assertIsString($bytes);

            $storage->responseAttachments()->add(new Attachment(
                '<'.$cid.'>',
                'cipher',
                'cipher',
                'application/ciphervalue',
                MemoryStream::create()->write($bytes)->rewind(),
            ));

            $cipherValue->textContent = '';
            $include = $document->toUnsafeDocument()->createElementNS(self::XOP, 'xop:Include');
            $include->setAttribute('href', 'cid:'.$cid);
            $cipherValue->appendChild($include);
            ++$moved;
        }

        return $moved;
    }

    /**
     * @return list<Element>
     */
    private function cipherValues(Document $document): array
    {
        $values = [];
        foreach ($document->toUnsafeDocument()->getElementsByTagNameNS(self::XENC, 'CipherValue') as $element) {
            if ($element instanceof Element) {
                $values[] = $element;
            }
        }

        return $values;
    }

    private function resolve(Document $document, AttachmentStorageInterface $storage): void
    {
        (new ResolveOptimizedBytes(
            AttachmentParts::response($storage, ExternalPartCoverage::Content),
        ))(new WsseContext($document, SoapVersion::Soap12, $this->profile(), new ExchangeKeys()));
    }

    private function decrypt(WsseSignatureFixture $fixture, Document $document): void
    {
        (new Decrypt($fixture->leafKey))(
            new WsseContext($document, SoapVersion::Soap12, $this->profile(), new ExchangeKeys()),
        );
    }

    private function profile(): SecurityProfile
    {
        return new SecurityProfile(
            crypto: new CryptoPolicy(dataEncryptionMethod: DataEncryptionMethod::AES256_GCM),
        );
    }
}
