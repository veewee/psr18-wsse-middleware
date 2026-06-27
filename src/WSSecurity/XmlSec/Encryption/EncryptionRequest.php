<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption;

use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\KeyEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\KeyHandle;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\KeyIdentifier;

/**
 * The inputs to a single encryption operation. The recipient certificate is named by a KeyHandle (PEM
 * material) the OpenSSL\ module resolves internally.
 */
final readonly class EncryptionRequest
{
    /**
     * @param non-empty-list<Part> $parts
     */
    public function __construct(
        public array $parts,
        public KeyHandle $recipientCertificate,
        public KeyIdentifier $keyIdentifier,
        public DataEncryptionMethod $dataEncryptionMethod,
        public KeyEncryptionMethod $keyEncryptionMethod,
    ) {
    }
}
