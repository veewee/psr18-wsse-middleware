<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption;

use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\KeyTransportAlgorithm;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\KeyIdentifier;

/**
 * The inputs to a single encryption operation. The recipient certificate carries the PEM material the
 * OpenSSL\ module resolves internally.
 */
final readonly class EncryptionRequest
{
    /**
     * @param non-empty-list<Part> $parts
     */
    public function __construct(
        public array $parts,
        public Certificate $recipientCertificate,
        public KeyIdentifier $keyIdentifier,
        public DataEncryptionMethod $dataEncryptionMethod,
        public KeyTransportAlgorithm $keyTransportAlgorithm,
    ) {
    }
}
