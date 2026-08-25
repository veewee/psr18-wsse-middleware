<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

use InvalidArgumentException;
use LogicException;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\KeyEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\KeyTransportAlgorithm;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\UnsupportedAttachmentCoverage;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\EncKeyRef;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\IssuerSerialKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\ThumbprintKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\X509SubjectKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdConvention;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\Xml\Query;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptionRequest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptionTarget;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\Encryptor;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\ExternalPartEncryption;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\XmlEncryptor;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\EncryptionFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartCoverage;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalParts;
use Soap\Psr18WsseMiddleware\XmlSecurity\KeyIdentifier;
use Soap\Psr18WsseMiddleware\XmlSecurity\TargetLocator;
use VeeWee\Xml\Dom\Document;

/**
 * Encrypts the requested parts of the outbound message via XML-Enc. Configuration:
 *   - the recipient public certificate, used to wrap the session key
 *   - which key-reference type to put in xenc:EncryptedKey/ds:KeyInfo, via EncKeyRef
 *   - which parts to encrypt (default: Body only; override via withParts)
 *   - algorithms (default: the profile carried on the context; override per block)
 *
 * For the direct-reference path (EncKeyRef::BinarySecurityToken), the block embeds a
 * wsse:BinarySecurityToken before encrypting, locates it by content in the Security header to read its
 * wsu:Id, and points a DirectReferenceKeyIdentifier at it. For the inline key-reference types (SKI / IssuerSerial /
 * Thumbprint) no token is embedded; the strategy derives its content from the recipient certificate alone.
 *
 * The Security header is guaranteed to exist before the encryptor runs. Algorithm resolution order:
 * per-block override, then the profile carried on the context.
 *
 * Intended position in the outbound list: after Outbound\Signature (sign-then-encrypt). The engine
 * places xenc:EncryptedKey before ds:Signature in the Security header; this block takes no action on it.
 */
final class Encryption implements OutboundAction
{
    /**
     * The only encryption mode this package emits: an attachment's content is encrypted while its MIME
     * headers stay readable. Attachment-Complete also encrypts the headers, and no policy can require it,
     * since a peer validates the coverage of a signature and never of an encryption. Inbound is another
     * matter, and Decrypt accepts both.
     */
    private const SWA_CONTENT_ONLY_TYPE = 'http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Only';

    /**
     * Declared inside the CipherReference so a receiver knows the referenced part holds ciphertext rather than
     * the original bytes.
     */
    private const SWA_CIPHERTEXT_TRANSFORM = 'http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Ciphertext-Transform';

    private const OPAQUE_MEDIA_TYPE = 'application/octet-stream';

    private const XOP_NAMESPACE = 'http://www.w3.org/2004/08/xop/include';

    /** @var list<Part>|null */
    private ?array $parts = null;

    private ?DataEncryptionMethod $dataEncryptionMethod = null;
    private ?KeyEncryptionMethod $keyEncryptionMethod = null;
    private ?KeyTransportAlgorithm $keyTransportAlgorithm = null;
    private ?ExternalParts $attachments = null;

    private XmlEncryptor $encryptor;
    private readonly TargetLocator $targetLocator;

    public function __construct(
        private readonly Certificate $recipientCertificate,
        private readonly EncKeyRef $encKeyRef = EncKeyRef::SubjectKeyIdentifier,
    ) {
        // The WS-Security profile mandates wsu:Id on the xenc:EncryptedData, so the block injects the wsu:Id
        // convention on both sides. The engine's own default (xml:id) would break the WSSE wire format.
        $convention = new WsuIdConvention();
        $this->encryptor = Encryptor::create($convention);
        // Only the read half, and only for the XOP guard: this block resolves a target to inspect it, never
        // to stamp anything. The engine resolves them again for the encryption itself.
        $this->targetLocator = new TargetLocator($convention->lookup());
    }

    public function withEncryptor(XmlEncryptor $encryptor): self
    {
        $clone = clone $this;
        $clone->encryptor = $encryptor;

        return $clone;
    }

    /**
     * An empty list is refused rather than read as "the default": encrypting nothing still wraps a session key
     * and appends an xenc:EncryptedKey, so the Body would leave in cleartext under a message that reads as
     * encrypted everywhere it is logged or captured.
     *
     * Declared as a plain list rather than a non-empty one on purpose: a static constraint is not a guard, and
     * the list a caller passes is routinely built from configuration a type checker never sees.
     *
     * @param list<Part> $parts
     */
    public function withParts(array $parts): self
    {
        $clone = clone $this;
        $clone->parts = $parts;

        return $clone;
    }

    /**
     * Encrypts the message's attachments alongside its in-document parts, under the same session key.
     *
     * Under the same key and in the same operation, not as a second block: the profile wants one
     * xenc:EncryptedKey whose single ReferenceList names the in-document parts and the attachment parts
     * together, and a receiver refuses a second key in the header.
     *
     * The sealed parts are written back with an opaque media type, since their bytes are no longer of the type
     * they claimed. The original type is recorded on the xenc:EncryptedData so the far side can restore it.
     *
     * Pass AttachmentParts::request() for the outbound side. To also sign them, put Outbound\Signature first
     * with the same registration: it digests the plaintext, and this block then replaces it with ciphertext.
     */
    public function withAttachments(ExternalParts $attachments): self
    {
        $clone = clone $this;
        $clone->attachments = $attachments;

        return $clone;
    }

    public function withDataEncryptionMethod(DataEncryptionMethod $method): self
    {
        $clone = clone $this;
        $clone->dataEncryptionMethod = $method;

        return $clone;
    }

    /**
     * Overrides only the key-encryption method; the OAEP hash is resolved from the profile (or its default) at
     * apply time. For a method paired with a specific hash, use withKeyTransportAlgorithm.
     */
    public function withKeyEncryptionMethod(KeyEncryptionMethod $method): self
    {
        $clone = clone $this;
        $clone->keyEncryptionMethod = $method;

        return $clone;
    }

    /**
     * Overrides the whole key-transport choice atomically: an invalid method/hash pairing cannot be expressed,
     * and this override wins over withKeyEncryptionMethod and the profile.
     */
    public function withKeyTransportAlgorithm(KeyTransportAlgorithm $algorithm): self
    {
        $clone = clone $this;
        $clone->keyTransportAlgorithm = $algorithm;

        return $clone;
    }

    /**
     * @throws \Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException when the header cannot be created
     * @throws \Soap\Psr18WsseMiddleware\XmlSecurity\Exception\IdStampFailed when an encrypted part cannot carry a wsu:Id
     * @throws \Soap\Psr18WsseMiddleware\XmlSecurity\Exception\EncryptionFailed when encryption fails
     */
    public function __invoke(WsseContext $context): void
    {
        $document = $context->document();

        $security = SecurityHeader::forContext($context);

        $keyIdentifier = $this->resolveKeyIdentifier($context);
        $profile = $context->profile();

        $keyTransportAlgorithm = $this->keyTransportAlgorithm ?? KeyTransportAlgorithm::fromMethod(
            $this->keyEncryptionMethod ?? $profile->crypto()->keyEncryptionMethod(),
            $profile->crypto()->oaepHash(),
        );

        $parts = $this->parts ?? [Part::body()];
        $soapVersion = $context->soapVersion();
        $external = $this->externalPartEncryption();

        if ($parts === [] && $external === null) {
            // Encrypting nothing still wraps a session key and appends an xenc:EncryptedKey, so the message
            // would leave with a plaintext Body while reading as encrypted in every log and capture of it.
            throw new InvalidArgumentException('Encryption needs at least one part to encrypt.');
        }
        $request = new EncryptionRequest(
            container: $security->element(),
            targets: array_map(
                static fn (Part $part): EncryptionTarget => new EncryptionTarget(
                    $part->toTarget($soapVersion),
                    // A null mode marks a signing-only part (securityHeaderContents/soapHeaders): not encryptable.
                    $part->encryptionMode() ?? throw new LogicException(
                        'A signing-only Part (securityHeaderContents/soapHeaders) cannot be encrypted.',
                    ),
                ),
                $parts,
            ),
            recipientCertificate: $this->recipientCertificate,
            keyIdentifier: $keyIdentifier,
            dataEncryptionMethod: $this->dataEncryptionMethod ?? $profile->crypto()->dataEncryptionMethod(),
            keyTransportAlgorithm: $keyTransportAlgorithm,
            externalParts: $external,
        );

        $this->assertNoOptimizedContent($document, $request);

        $result = $this->encryptor->encrypt($document, $request);

        if ($this->attachments !== null) {
            $this->attachments->replace($this->opaque($result->sealedParts));
        }

        // The engine appends the encrypted key; which order this header must be in is the profile's rule.
        $security->sort();
    }

    /**
     * The SwA type and transform are this block's to declare, exactly as it owns lowering a Part into an
     * EncryptionTarget. The engine is handed two URIs and a list of parts and never learns they are
     * attachments.
     *
     * Collected here rather than at wiring time because the storage holds the message in flight.
     */
    private function externalPartEncryption(): ?ExternalPartEncryption
    {
        if ($this->attachments === null) {
            return null;
        }

        if ($this->attachments->coverage() !== ExternalPartCoverage::Content) {
            throw UnsupportedAttachmentCoverage::outboundEncryption();
        }

        return new ExternalPartEncryption(
            $this->attachments->collectSealed(),
            self::SWA_CONTENT_ONLY_TYPE,
            self::SWA_CIPHERTEXT_TRANSFORM,
        );
    }

    /**
     * Ciphertext is not of the media type the plaintext was, and saying otherwise invites a reader to parse
     * it. The type the far side needs in order to restore the part travels on the xenc:EncryptedData instead.
     */
    private function opaque(ExternalPartList $sealed): ExternalPartList
    {
        $opaque = [];
        foreach ($sealed as $part) {
            $opaque[] = $part->withContent($part->content, self::OPAQUE_MEDIA_TYPE);
        }

        return ExternalPartList::of(...$opaque);
    }

    /**
     * Refuses to encrypt an element whose content is, or contains, an xop:Include.
     *
     * A disclosure guard rather than a convenience check. The include is only a pointer: encrypting the
     * element that holds it produces ciphertext over the pointer while the bytes themselves travel in the
     * clear in their own MIME part, and the message still satisfies a policy check for "that element is
     * encrypted". Encrypting the part an include points at is the supported path and is what
     * withAttachments() does.
     *
     * @throws EncryptionFailed
     */
    private function assertNoOptimizedContent(Document $document, EncryptionRequest $request): void
    {
        foreach ($request->targets as $target) {
            try {
                $element = $this->targetLocator->locate($document, $target->target);
            } catch (IdReferenceException) {
                // Not this guard's verdict to give. The engine resolves every target itself and refuses the
                // whole operation when one is missing, so nothing gets encrypted either way.
                continue;
            }

            $includes = Query::elements(
                $document,
                './/xop:Include | self::xop:Include',
                $element,
                ['xop' => self::XOP_NAMESPACE],
            );

            if (count($includes) > 0) {
                throw EncryptionFailed::withReason(
                    'An element carrying an xop:Include cannot be encrypted: that would protect the reference '
                    .'while the referenced bytes travel in the clear. Encrypt the attachment instead.',
                );
            }
        }
    }

    private function resolveKeyIdentifier(WsseContext $context): KeyIdentifier
    {
        return match ($this->encKeyRef) {
            EncKeyRef::SubjectKeyIdentifier => new X509SubjectKeyIdentifier(),
            EncKeyRef::IssuerSerial => new IssuerSerialKeyIdentifier(),
            EncKeyRef::Thumbprint => new ThumbprintKeyIdentifier(),
            EncKeyRef::BinarySecurityToken => (new BinarySecurityToken($this->recipientCertificate))
                ->embedAsDirectReference($context),
        };
    }
}
