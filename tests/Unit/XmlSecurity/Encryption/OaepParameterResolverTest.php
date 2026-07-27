<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Encryption;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\Exception\UnsupportedAlgorithmException;
use Soap\Psr18WsseMiddleware\Algorithm\KeyEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\KeyTransportAlgorithm;
use Soap\Psr18WsseMiddleware\Algorithm\OaepHash;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\OaepParameterResolver;
use VeeWee\Xml\Dom\Document;

final class OaepParameterResolverTest extends TestCase
{
    private const XENC = 'http://www.w3.org/2001/04/xmlenc#';
    private const XENC11 = 'http://www.w3.org/2009/xmlenc11#';
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';
    private const RSA_OAEP = 'http://www.w3.org/2009/xmlenc11#rsa-oaep';
    private const RSA_OAEP_MGF1P = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';
    private const RSA_1_5 = 'http://www.w3.org/2001/04/xmlenc#rsa-1_5';
    private const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
    private const SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
    private const MGF1_SHA1 = 'http://www.w3.org/2009/xmlenc11#mgf1sha1';
    private const MGF1_SHA256 = 'http://www.w3.org/2009/xmlenc11#mgf1sha256';

    public function test_it_resolves_a_bare_method_to_oaep_sha1(): void
    {
        $element = $this->encryptionMethod(self::RSA_OAEP, []);

        $algorithm = (new OaepParameterResolver())->resolve(
            KeyEncryptionMethod::RSA_OAEP,
            $element,
            CryptoPolicy::default(),
        );

        static::assertSame(KeyTransportAlgorithm::oaepSha1()->method, $algorithm->method);
        static::assertSame(OaepHash::Sha1, $algorithm->oaepHash);
    }

    public function test_rsa_1_5_is_rejected_by_the_default_policy(): void
    {
        // The default allow-list excludes rsa-1_5 (Bleichenbacher/Marvin); the short-circuit that skips OAEP
        // resolution must not also skip the allow-list, or a peer could force PKCS#1 v1.5 unwrapping.
        $element = $this->encryptionMethod(self::RSA_1_5, []);

        $this->expectRejection($element, KeyEncryptionMethod::RSA_1_5);
    }

    public function test_rsa_1_5_resolves_without_an_oaep_hash_when_the_policy_admits_it(): void
    {
        // Opting in is still possible for a legacy peer; the method carries no OAEP hash.
        $element = $this->encryptionMethod(self::RSA_1_5, []);

        $algorithm = (new OaepParameterResolver())->resolve(
            KeyEncryptionMethod::RSA_1_5,
            $element,
            new CryptoPolicy(acceptedKeyEncryptionMethods: [KeyEncryptionMethod::RSA_1_5]),
        );

        static::assertSame(KeyEncryptionMethod::RSA_1_5, $algorithm->method);
        static::assertNull($algorithm->oaepHash);
    }

    public function test_a_policy_excluding_oaep_rejects_an_oaep_method(): void
    {
        // The same gate must cover the OAEP methods, not just the legacy one.
        $element = $this->encryptionMethod(self::RSA_OAEP, []);

        $this->expectRejection(
            $element,
            KeyEncryptionMethod::RSA_OAEP,
            new CryptoPolicy(acceptedKeyEncryptionMethods: [KeyEncryptionMethod::RSA_OAEP_MGF1P]),
        );
    }

    public function test_it_resolves_explicit_sha256_children(): void
    {
        $element = $this->encryptionMethod(self::RSA_OAEP, [
            ['DigestMethod', self::DS, self::SHA256],
            ['MGF', self::XENC11, self::MGF1_SHA256],
        ]);

        $algorithm = (new OaepParameterResolver())->resolve(
            KeyEncryptionMethod::RSA_OAEP,
            $element,
            CryptoPolicy::default(),
        );

        static::assertSame(OaepHash::Sha256, $algorithm->oaepHash);
    }

    public function test_a_digest_mgf_mismatch_is_rejected(): void
    {
        $element = $this->encryptionMethod(self::RSA_OAEP, [
            ['DigestMethod', self::DS, self::SHA256],
            ['MGF', self::XENC11, self::MGF1_SHA1],
        ]);

        $this->expectRejection($element, KeyEncryptionMethod::RSA_OAEP);
    }

    public function test_a_disallowed_digest_is_rejected(): void
    {
        $element = $this->encryptionMethod(self::RSA_OAEP, [
            ['DigestMethod', self::DS, self::SHA384],
            ['MGF', self::XENC11, self::MGF1_SHA256],
        ]);

        $this->expectRejection($element, KeyEncryptionMethod::RSA_OAEP);
    }

    public function test_the_legacy_mgf1p_uri_rejects_an_mgf_child(): void
    {
        $element = $this->encryptionMethod(self::RSA_OAEP_MGF1P, [
            ['MGF', self::XENC11, self::MGF1_SHA1],
        ]);

        $this->expectRejection($element, KeyEncryptionMethod::RSA_OAEP_MGF1P);
    }

    public function test_the_legacy_mgf1p_uri_rejects_a_non_sha1_digest(): void
    {
        $element = $this->encryptionMethod(self::RSA_OAEP_MGF1P, [
            ['DigestMethod', self::DS, self::SHA256],
        ]);

        $this->expectRejection($element, KeyEncryptionMethod::RSA_OAEP_MGF1P);
    }

    public function test_the_legacy_mgf1p_uri_resolves_a_bare_method_to_sha1(): void
    {
        $element = $this->encryptionMethod(self::RSA_OAEP_MGF1P, []);

        $algorithm = (new OaepParameterResolver())->resolve(
            KeyEncryptionMethod::RSA_OAEP_MGF1P,
            $element,
            CryptoPolicy::default(),
        );

        static::assertSame(OaepHash::Sha1, $algorithm->oaepHash);
    }

    public function test_a_non_empty_oaep_params_is_rejected(): void
    {
        $element = $this->encryptionMethod(self::RSA_OAEP, [
            ['DigestMethod', self::DS, self::SHA256],
            ['MGF', self::XENC11, self::MGF1_SHA256],
            ['OAEPparams', self::XENC, null, base64_encode('label')],
        ]);

        $this->expectRejection($element, KeyEncryptionMethod::RSA_OAEP);
    }

    public function test_a_profile_excluding_sha256_is_rejected(): void
    {
        $element = $this->encryptionMethod(self::RSA_OAEP, [
            ['DigestMethod', self::DS, self::SHA256],
            ['MGF', self::XENC11, self::MGF1_SHA256],
        ]);

        $this->expectRejection(
            $element,
            KeyEncryptionMethod::RSA_OAEP,
            new CryptoPolicy(acceptedOaepHashes: [OaepHash::Sha1]),
        );
    }

    public function test_a_garbage_digest_uri_is_rejected(): void
    {
        $element = $this->encryptionMethod(self::RSA_OAEP, [
            ['DigestMethod', self::DS, 'urn:not-a-digest'],
        ]);

        $this->expectRejection($element, KeyEncryptionMethod::RSA_OAEP);
    }

    private function expectRejection(
        Element $element,
        KeyEncryptionMethod $method,
        ?CryptoPolicy $profile = null,
    ): void {
        // Every disallowed, inconsistent, or garbage input surfaces as the same exception type, so the caller
        // can fold them all into one uniform failure with no distinguishing detail.
        $this->expectException(UnsupportedAlgorithmException::class);

        (new OaepParameterResolver())->resolve($method, $element, $profile ?? CryptoPolicy::default());
    }

    /**
     * @param list<array{0: string, 1: string, 2: string|null, 3?: string}> $children
     */
    private function encryptionMethod(string $algorithm, array $children): Element
    {
        $rendered = '';
        foreach ($children as $child) {
            [$localName, $namespace, $childAlgorithm] = $child;
            $text = $child[3] ?? '';
            $prefix = $namespace === self::DS ? 'ds' : ($namespace === self::XENC11 ? 'xenc11' : 'xenc');
            $attr = $childAlgorithm === null ? '' : ' Algorithm="'.$childAlgorithm.'"';
            $rendered .= '<'.$prefix.':'.$localName.$attr.'>'.$text.'</'.$prefix.':'.$localName.'>';
        }

        $document = Document::fromXmlString(
            '<xenc:EncryptionMethod xmlns:xenc="'.self::XENC.'"'
            .' xmlns:xenc11="'.self::XENC11.'" xmlns:ds="'.self::DS.'"'
            .' Algorithm="'.$algorithm.'">'.$rendered.'</xenc:EncryptionMethod>'
        );

        $element = $document->toUnsafeDocument()->documentElement;
        static::assertInstanceOf(Element::class, $element);

        return $element;
    }
}
