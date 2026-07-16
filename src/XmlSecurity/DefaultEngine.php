<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

use Soap\Psr18WsseMiddleware\OpenSSL\CertificateTrust;
use Soap\Psr18WsseMiddleware\OpenSSL\Cipher;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\OpenSSL\KeyTransport;
use Soap\Psr18WsseMiddleware\OpenSSL\Signer as OpenSslSigner;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Manipulator\WsuIdMinter;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\DomCanonicalizer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\Decryptor;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptedDataBuilder;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptedDataReader;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptedKeyBuilder;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptedKeyReader;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\Encryptor;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\SessionKeyFactory;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\XmlDecryptor;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\XmlEncryptor;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\DigestCalculator;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\KeyInfoBuilder;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\ReferenceCollector;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\SignedInfoBuilder;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\Signer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\XmlSigner;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\AlgorithmPolicyEnforcer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\CertificateExtractor;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\DigestVerifier;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\ReferenceResolver;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\Resolver;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignatureLocator;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignatureValidator;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfoParser;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\Verifier;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\XmlSignatureVerifier;

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
            new CertificateExtractor(),
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
