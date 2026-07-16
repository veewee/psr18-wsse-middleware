<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Inbound;

use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\XmlSecurity\DefaultEngine;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\DecryptionRequest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\XmlDecryptor;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\DecryptionFailed;

/**
 * Decrypts the xenc:EncryptedData parts of the inbound message by delegating to the XmlDecryptor SPI. The
 * recipient private key is provided at construction time and the decryptor resolves it internally; the
 * document is mutated in place (each EncryptedData replaced by its plaintext nodes).
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
        $this->decryptor = DefaultEngine::decryptor();
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
        try {
            $this->decryptor->decrypt($context->document(), new DecryptionRequest($this->privateKey, $context->profile()));
        } catch (DecryptionFailed $exception) {
            throw SecurityFault::inboundFailure($exception);
        }
    }
}
