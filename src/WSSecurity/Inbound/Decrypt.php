<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Inbound;

use InvalidArgumentException;
use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\AttachmentEncryptedDataType;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\KeyRequest;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\SymmetricKeySource;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\EstablishedSessionKeyResolver;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\DecryptionRequest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\Decryptor;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\External\ExternalPartDecryption;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\XmlDecryptor;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\DecryptionFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalParts;
use Throwable;

/**
 * Decrypts the xenc:EncryptedData parts of the inbound message by delegating to the XmlDecryptor SPI. The
 * recipient private key is provided at construction time and the decryptor resolves it internally; the
 * document is mutated in place (each EncryptedData replaced by its plaintext nodes).
 *
 * The wrapped session key is read from the Security header addressed to this receiver, the same scope the
 * signature verifier and the timestamp validator use. Anyone can wrap a key to a public certificate, so a
 * message carrying no header for us is refused rather than decrypted against an xenc:EncryptedKey found
 * elsewhere in the envelope, which nothing marks as intended for this recipient.
 *
 * The header itself is left as the sender wrote it. The xenc:EncryptedKey and its xenc:ReferenceList stay in
 * place, so the DataReference entries end up naming ids this pass just removed. Pruning them would mutate a
 * header a signature may still cover, and the reference URI is a plain anyURI nothing resolves a second time,
 * so the dangling entry costs nothing while the removal risks a verification.
 *
 * A response encrypted under a key this exchange already established carries no xenc:EncryptedKey at all: each
 * xenc:EncryptedData names the key instead, and it is resolved from what the exchange holds. Such a deployment
 * needs no private key here. A pre-shared secret is the one case that has to be handed over, because no
 * outbound direction established it.
 *
 * Every decryption failure, whatever its cause, collapses to one SecurityFault with a non-identifying
 * message. The underlying reason is chained for operator logs only and is never forwarded to a remote peer.
 * The part-count cap and the uniform internal failure live in the decryptor, so this block adds no second
 * gate and no distinguisher.
 */
final class Decrypt implements InboundAction
{
    private XmlDecryptor $decryptor;
    private ?ExternalParts $attachments = null;

    private ?SymmetricKeySource $symmetricKey = null;

    /**
     * @param ?Key $privateKey the key that unwraps an xenc:EncryptedKey. Null for a deployment whose peer
     *        encrypts under a key the exchange already established, which wraps nothing
     */
    public function __construct(
        private readonly ?Key $privateKey = null,
    ) {
        // The WS-Security profile tags xenc:EncryptedData with wsu:Id, so the decryptor resolves references
        // through the wsu:Id convention (native namespace-less @Id from interop peers is still accepted too).
        // Only the read half is handed over: nothing inbound mints, and a class that holds no minter cannot.
        $this->decryptor = Decryptor::create((new WsuIdConvention())->lookup());
    }

    /**
     * Decrypts the message's encrypted attachments as well as its in-document parts.
     *
     * Register these whenever the peer may encrypt an attachment: an xenc:EncryptedData naming a part is
     * refused when none were supplied, rather than skipped, so an encrypted attachment never reaches the
     * caller still encrypted while the message reads as successfully decrypted.
     *
     * Pass AttachmentParts::response() for the inbound side. Put this block before Inbound\VerifySignature so
     * the signature is checked against the plaintext, which is what the far side digested.
     */
    public function withAttachments(ExternalParts $attachments): self
    {
        $clone = clone $this;
        $clone->attachments = $attachments;

        return $clone;
    }

    public function withDecryptor(XmlDecryptor $decryptor): self
    {
        $clone = clone $this;
        $clone->decryptor = $decryptor;

        return $clone;
    }

    /**
     * Registers the source of a secret no outbound direction established, so parts encrypted under it can be
     * opened. Only a pre-shared key needs this: a wrapped or derived key was established while the request was
     * written, and the exchange already holds it.
     *
     * The secret is registered when the block runs rather than now, because the exchange it belongs to is the
     * one in flight. Registration is idempotent, so both inbound blocks may hold the same source.
     */
    public function withSymmetricKey(SymmetricKeySource $key): self
    {
        $clone = clone $this;
        $clone->symmetricKey = $key;

        return $clone;
    }

    /**
     * Every part registered on this block must come back opened.
     *
     * Registering an attachment here is the requirement that it arrive encrypted, the same way registering
     * one on VerifySignature requires that it arrive signed. A message whose xenc:EncryptedData named only
     * in-document parts leaves the attachment in the clear, and accepting that would hand the caller bytes
     * that crossed the network unprotected while their configuration says otherwise.
     *
     * @throws DecryptionFailed
     */
    private function assertEveryRegisteredPartOpened(
        ?ExternalPartList $registeredAttachments,
        ExternalPartList $opened,
    ): void {
        foreach ($registeredAttachments ?? ExternalPartList::of() as $part) {
            if ($opened->byReference($part->reference) === null) {
                throw DecryptionFailed::withReason('A registered attachment was not encrypted.');
            }
        }
    }

    /**
     * The two SwA URIs are this block's to require, exactly as the outbound twin owns emitting them. The
     * engine is told what to demand and never learns these are attachments.
     */
    private function externalPartDecryption(): ?ExternalPartDecryption
    {
        $attachments = $this->attachments;
        if ($attachments === null) {
            return null;
        }

        return new ExternalPartDecryption(
            $attachments->collectSealed(),
            AttachmentEncryptedDataType::for($attachments->coverage())->value,
            AttachmentEncryptedDataType::CIPHERTEXT_TRANSFORM,
        );
    }

    /**
     * @throws SecurityFault
     */
    public function __invoke(WsseContext $context): void
    {
        $document = $context->document();

        try {
            $container = SecurityHeader::locate($document, $context->soapVersion(), $context->profile()->actorOrRole())
                ?? throw DecryptionFailed::withReason('The message carries no Security header for this receiver.');

            $this->symmetricKey?->resolve($context, KeyRequest::preferably(1));

            $external = $this->externalPartDecryption();
            $result = $this->decryptor->decrypt(
                $document,
                new DecryptionRequest(
                    $container,
                    $this->privateKey,
                    $context->profile()->crypto(),
                    $external,
                    new EstablishedSessionKeyResolver($context->keys(), (new WsuIdConvention())->lookup()),
                ),
            );

            $this->assertEveryRegisteredPartOpened($external?->parts, $result->openedParts);

            // Only the parts an xenc:EncryptedData actually named come back, so an attachment that arrived in
            // the clear is absent here and is left exactly as it was rather than dropped.
            $this->attachments?->replace($result->openedParts);
        } catch (DecryptionFailed | WsseHeaderException | InvalidArgumentException $exception) {
            throw SecurityFault::inboundFailure($exception);
        } catch (Throwable $foreign) {
            // The decryptor is a replaceable seam, so a third-party one raises types this package never
            // declares. This is the padding-oracle channel, where one distinguishable outcome per cause is
            // precisely what recovers a plaintext, and the code cannot tell a bug apart from a deliberate type.
            // Nothing is lost locally: the original is chained, so an operator still gets its message and trace.
            throw SecurityFault::inboundFailure($foreign);
        }
    }
}
