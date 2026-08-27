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
 * an encryption together.
 *
 * Where the xenc:ReferenceList goes is the caller\'s too, and it decides whether a ds:KeyInfo is needed at all. A
 * list nested inside the xenc:EncryptedKey ties the key to the parts itself, so nothing else has to; a list
 * standing in the container has no such tie, so each xenc:EncryptedData names its own key. The caller states
 * both, because which is possible depends on whether anything else has taken the key.
 */
final readonly class EncryptionRequest
{
    /**
     * @param list<EncryptionTarget> $targets may be empty when external parts are supplied: encrypting only
     *        attachments is a legitimate configuration. The Encryptor refuses a request that would encrypt
     *        nothing at all
     * @param ?KeyIdentifier $keyIdentifier written as a ds:KeyInfo on every xenc:EncryptedData this operation
     *        produces; null emits none, leaving the receiver to resolve the key from where the list sits
     * @param ?Element $nestReferenceListIn the element the xenc:ReferenceList becomes a child of; null appends
     *        it to the container instead
     */
    public function __construct(
        public Element $container,
        public array $targets,
        #[SensitiveParameter] public SessionKey $sessionKey,
        public DataEncryptionMethod $dataEncryptionMethod,
        public ?KeyIdentifier $keyIdentifier = null,
        public ?ExternalPartEncryption $externalParts = null,
        public ?Element $nestReferenceListIn = null,
    ) {
    }
}
