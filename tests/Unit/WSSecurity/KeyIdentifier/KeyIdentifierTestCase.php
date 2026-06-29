<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\KeyIdentifier;

use Dom\Element;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use VeeWee\Xml\Dom\Document;

abstract class KeyIdentifierTestCase extends TestCase
{
    protected const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    protected const WSSE11 = 'http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd';
    protected const DS = 'http://www.w3.org/2000/09/xmldsig#';

    protected function document(): Document
    {
        return Document::fromXmlString('<root/>');
    }

    protected function firstChildElement(Element $element): Element
    {
        foreach ($element->childNodes as $child) {
            if ($child instanceof Element) {
                return $child;
            }
        }

        static::fail('No child element found.');
    }

    /**
     * @param non-empty-string $localName
     */
    protected function childByLocalName(Element $element, string $localName): Element
    {
        foreach ($element->childNodes as $child) {
            if ($child instanceof Element && $child->localName === $localName) {
                return $child;
            }
        }

        static::fail(sprintf('No <%s> child element found.', $localName));
    }

    protected function certificate(): Certificate
    {
        $path = tempnam(sys_get_temp_dir(), 'wsse-ki-');
        static::assertIsString($path);
        file_put_contents($path, "[req]\ndistinguished_name = dn\nx509_extensions = v3\n[dn]\n[v3]\nsubjectKeyIdentifier = hash\n");
        $config = ['config' => $path];

        $private = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA] + $config);
        static::assertInstanceOf(OpenSSLAsymmetricKey::class, $private);

        $csr = openssl_csr_new(['commonName' => 'key-identifier-test'], $private, $config);
        static::assertNotFalse($csr);

        $certificate = openssl_csr_sign($csr, null, $private, 365, $config + ['x509_extensions' => 'v3'], 4242);
        static::assertNotFalse($certificate);

        static::assertTrue(openssl_x509_export($certificate, $certificatePem));
        static::assertIsString($certificatePem);

        return new Certificate($certificatePem);
    }
}
