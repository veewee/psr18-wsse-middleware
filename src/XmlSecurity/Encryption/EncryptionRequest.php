<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\KeyTransportAlgorithm;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\XmlSecurity\KeyIdentifier;

/**
 * The inputs to a single encryption operation. The recipient certificate carries the PEM material the
 * OpenSSL\ module resolves internally.
 */
final readonly class EncryptionRequest
{
    /**
     * @param non-empty-list<EncryptionTarget> $targets
     */
    public function __construct(
        public array $targets,
        public Certificate $recipientCertificate,
        public KeyIdentifier $keyIdentifier,
        public DataEncryptionMethod $dataEncryptionMethod,
        public KeyTransportAlgorithm $keyTransportAlgorithm,
    ) {
    }
}
