<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\Middleware;

use Dom\Element;
use Http\Client\Common\Plugin;
use Http\Client\Common\PluginClient;
use Http\Discovery\Psr17FactoryDiscovery;
use Http\Mock\Client;
use Nyholm\Psr7\Request;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Wsa\WsaNamespace;
use Soap\Psr18WsseMiddleware\WsaMiddleware;
use VeeWee\Xml\Dom\Document;
use VeeWee\Xml\Exception\DoctypeNotAllowedException;

final class WsaMiddlewareTest extends TestCase
{
    public function test_it_is_a_middleware(): void
    {
        static::assertInstanceOf(Plugin::class, new WsaMiddleware());
    }

    public function test_it_adds_2005_addressing_headers_by_default(): void
    {
        $body = $this->sendThrough(new WsaMiddleware());

        $ns = WsaNamespace::W3c200508->value;
        static::assertSame('myaction', $this->single($body, $ns, 'Action')->textContent);
        static::assertSame('/endpoint', $this->single($body, $ns, 'To')->textContent);
        static::assertMatchesRegularExpression(
            '/^uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i',
            $this->single($body, $ns, 'MessageID')->textContent
        );
        static::assertSame(
            WsaNamespace::W3c200508->anonymousUri(),
            $this->single($body, $ns, 'Address')->textContent
        );
    }

    public function test_it_can_emit_2004_addressing_headers(): void
    {
        $body = $this->sendThrough(new WsaMiddleware(WsaNamespace::Submission200408));

        $ns = WsaNamespace::Submission200408->value;
        static::assertCount(1, $this->all($body, $ns, 'Action'));
        static::assertCount(0, $this->all($body, WsaNamespace::W3c200508->value, 'Action'));
        static::assertSame(
            WsaNamespace::Submission200408->anonymousUri(),
            $this->single($body, $ns, 'Address')->textContent
        );
    }

    public function test_a_custom_reply_to_address_is_honoured(): void
    {
        $body = $this->sendThrough(new WsaMiddleware(replyToAddress: 'https://example.test/reply'));

        static::assertSame(
            'https://example.test/reply',
            $this->single($body, WsaNamespace::W3c200508->value, 'Address')->textContent
        );
    }

    public function test_it_rejects_a_request_body_carrying_a_doctype(): void
    {
        $mockClient = new Client(Psr17FactoryDiscovery::findResponseFactory());
        $client = new PluginClient($mockClient, [new WsaMiddleware()]);
        $mockClient->addResponse(new Response(200));
        $body = '<?xml version="1.0"?><!DOCTYPE x>'
            .'<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Body/></soap:Envelope>';

        $this->expectException(DoctypeNotAllowedException::class);
        $client->sendRequest(new Request('POST', '/endpoint', ['SOAPAction' => 'a'], $body));
    }

    private function sendThrough(WsaMiddleware $middleware): string
    {
        $mockClient = new Client(Psr17FactoryDiscovery::findResponseFactory());
        $client = new PluginClient($mockClient, [$middleware]);
        $mockClient->addResponse(new Response(200));
        $soapRequest = (string) file_get_contents(FIXTURE_DIR.'/soap/empty-request.xml');

        $client->sendRequest(new Request('POST', '/endpoint', ['SOAPAction' => 'myaction'], $soapRequest));

        return (string) $mockClient->getRequests()[0]->getBody();
    }

    /** @return list<Element> */
    private function all(string $body, string $namespace, string $localName): array
    {
        $document = Document::fromXmlString($body);
        $found = [];
        foreach ($document->toUnsafeDocument()->getElementsByTagNameNS($namespace, $localName) as $element) {
            $found[] = $element;
        }

        return $found;
    }

    private function single(string $body, string $namespace, string $localName): Element
    {
        $elements = $this->all($body, $namespace, $localName);
        static::assertCount(1, $elements, "Expected exactly one {$localName} in {$namespace}");

        return $elements[0];
    }
}
