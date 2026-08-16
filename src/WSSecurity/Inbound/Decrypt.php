<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Inbound;

use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\DecryptionRequest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\Decryptor;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\XmlDecryptor;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\DecryptionFailed;
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
 * Every decryption failure, whatever its cause, collapses to one SecurityFault with a non-identifying
 * message. The underlying reason is chained for operator logs only and is never forwarded to a remote peer.
 * The part-count cap and the uniform internal failure live in the decryptor, so this block adds no second
 * gate and no distinguisher.
 */
final class Decrypt implements InboundAction
{
    private XmlDecryptor $decryptor;

    public function __construct(
        private readonly Key $privateKey,
    ) {
        // The WS-Security profile tags xenc:EncryptedData with wsu:Id, so the decryptor resolves references
        // through the wsu:Id convention (native namespace-less @Id from interop peers is still accepted too).
        // Only the read half is handed over: nothing inbound mints, and a class that holds no minter cannot.
        $this->decryptor = Decryptor::create((new WsuIdConvention())->lookup());
    }

    public function withDecryptor(XmlDecryptor $decryptor): self
    {
        $clone = clone $this;
        $clone->decryptor = $decryptor;

        return $clone;
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

            $this->decryptor->decrypt(
                $document,
                new DecryptionRequest($container, $this->privateKey, $context->profile()->crypto()),
            );
        } catch (DecryptionFailed | WsseHeaderException $exception) {
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
