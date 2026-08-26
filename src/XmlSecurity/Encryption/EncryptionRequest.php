<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

use Dom\Element;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\External\ExternalPartEncryption;
use Soap\Psr18WsseMiddleware\XmlSecurity\KeyIdentifier;

/**
 * The inputs to a single encryption operation. The container is the element the xenc:ReferenceList is appended
 * to (the caller locates it. The WS-Security profile passes its wsse:Security header); the engine never reaches
 * into a SOAP header to find it.
 *
 * The session key arrives ready to use, and how it reaches the recipient is the caller\'s concern: wrapped in an
 * xenc:EncryptedKey, derived from one, or shared out of band. That is what lets one key protect a signature and
 * an encryption together. The key identifier is what each xenc:EncryptedData names it by.
 */
final readonly class EncryptionRequest
{
    /**
     * @param list<EncryptionTarget> $targets may be empty when external parts are supplied: encrypting only
     *        attachments is a legitimate configuration. The Encryptor refuses a request that would encrypt
     *        nothing at all
     * @param ?KeyIdentifier $keyIdentifier written as a ds:KeyInfo on every xenc:EncryptedData this operation
     *        produces; null emits none, leaving the receiver to resolve the key from context alone
     */
    public function __construct(
        public Element $container,
        public array $targets,
        #[SensitiveParameter] public SessionKey $sessionKey,
        public DataEncryptionMethod $dataEncryptionMethod,
        public ?KeyIdentifier $keyIdentifier = null,
        public ?ExternalPartEncryption $externalParts = null,
    ) {
    }
}
