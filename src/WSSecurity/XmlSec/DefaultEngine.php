<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec;

use Soap\Psr18WsseMiddleware\OpenSSL\CertificateFieldExtractor;
use Soap\Psr18WsseMiddleware\OpenSSL\CertificateTrust;
use Soap\Psr18WsseMiddleware\OpenSSL\Cipher;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\OpenSSL\KeyTransport;
use Soap\Psr18WsseMiddleware\OpenSSL\Signer as OpenSslSigner;
use Soap\Psr18WsseMiddleware\WSSecurity\Wsse\WsuIdMinter;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Canonicalization\DomCanonicalizer;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\Decryptor;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\EncryptedDataBuilder;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\EncryptedDataReader;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\EncryptedKeyBuilder;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\EncryptedKeyReader;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\Encryptor;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\SessionKeyFactory;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\XmlDecryptor;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\XmlEncryptor;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Signing\DigestCalculator;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Signing\KeyInfoBuilder;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Signing\ReferenceCollector;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Signing\SignedInfoBuilder;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Signing\Signer;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Signing\XmlSigner;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification\AlgorithmPolicyEnforcer;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification\CertificateExtractor;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification\DigestVerifier;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification\ReferenceResolver;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification\Resolver;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification\SignatureLocator;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification\SignatureValidator;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification\SignedInfoParser;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification\Verifier;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification\XmlSignatureVerifier;

/**
 * Assembles the default engine services from their concrete collaborators. This is the single internal
 * source of the default wiring so the crypto blocks can be constructed without hand-wiring the graph, while
 * the SPI seam is preserved: a caller may still pass a custom service to override the default.
 *
 * The signer and verifier share one canonicalizer instance because both digesting and signing read the same
 * canonical form.
 */
final class DefaultEngine
{
    public static function signer(): XmlSigner
    {
        $canonicalizer = new DomCanonicalizer();

        return new Signer(
            new ReferenceCollector(new WsuIdMinter(), new PartLocator()),
            new DigestCalculator($canonicalizer, new Digest()),
            new SignedInfoBuilder(),
            new KeyInfoBuilder(),
            $canonicalizer,
            new OpenSslSigner(),
        );
    }

    public static function verifier(): XmlSignatureVerifier
    {
        $canonicalizer = new DomCanonicalizer();

        return new Verifier(
            new SignatureLocator(),
            new SignedInfoParser(),
            new AlgorithmPolicyEnforcer(),
            new CertificateExtractor(new CertificateFieldExtractor()),
            new ReferenceResolver(),
            new DigestVerifier($canonicalizer, new Digest()),
            new SignatureValidator($canonicalizer, new OpenSslSigner()),
            new Resolver(new CertificateTrust()),
        );
    }

    public static function encryptor(): XmlEncryptor
    {
        return new Encryptor(
            new PartLocator(),
            new SessionKeyFactory(),
            new Cipher(),
            new EncryptedDataBuilder(new WsuIdMinter()),
            new KeyTransport(),
            new EncryptedKeyBuilder(),
        );
    }

    public static function decryptor(): XmlDecryptor
    {
        return new Decryptor(
            new EncryptedKeyReader(new KeyTransport()),
            new EncryptedDataReader(new Cipher()),
        );
    }
}
