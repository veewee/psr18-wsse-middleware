<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit;

use Http\Client\Common\Plugin;
use Http\Promise\FulfilledPromise;
use Http\Promise\Promise;
use Nyholm\Psr7\Request;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\InboundAction;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\OutboundAction;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WsseMiddleware;
use VeeWee\Xml\Exception\DoctypeNotAllowedException;
use function VeeWee\Xml\Dom\Builder\element;

final class WsseMiddlewareTest extends TestCase
{
    private const SOAP11_NS = 'http://schemas.xmlsoap.org/soap/envelope/';
    private const SOAP12_NS = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSSE_NS = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const WSU_NS = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';

    public function test_it_is_a_middleware(): void
    {
        static::assertInstanceOf(Plugin::class, new WsseMiddleware());
    }

    public function test_it_applies_outbound_blocks_to_the_request_body(): void
    {
        $block = new class implements OutboundAction {
            public function __invoke(WsseContext $context): void
            {
                $context->document()->manipulate(
                    static function (\Dom\Document $document): void {
                        $document->documentElement?->appendChild(
                            element('marker')($document->documentElement),
                        );
                    },
                );
            }
        };

        [$sentRequest, $response] = $this->runRequest(
            new WsseMiddleware([$block]),
            $this->soapRequest(self::SOAP12_NS),
        );

        static::assertStringContainsString('<marker', (string) $sentRequest->getBody());
        static::assertInstanceOf(ResponseInterface::class, $response);
    }

    public function test_it_runs_inbound_blocks_on_the_response_body(): void
    {
        $captured = null;
        $block = new class($captured) implements InboundAction {
            /** @param string|null $captured */
            public function __construct(private mixed &$captured)
            {
            }

            public function __invoke(WsseContext $context): void
            {
                $this->captured = $context->document()->locate(
                    static fn (\Dom\Document $document): string => $document->documentElement?->localName ?? '',
                );
            }
        };

        [, $response] = $this->runRequest(
            new WsseMiddleware([], [$block]),
            $this->soapRequest(self::SOAP12_NS),
            new Response(200, [], $this->soapEnvelope(self::SOAP12_NS)),
        );

        static::assertSame('Envelope', $captured);
        static::assertStringContainsString('Envelope', (string) $response->getBody());
    }

    public function test_it_derives_the_soap_version_from_the_envelope(): void
    {
        $version = null;
        $block = $this->versionCapturingBlock($version);

        $this->runRequest(new WsseMiddleware([$block]), $this->soapRequest(self::SOAP11_NS));
        static::assertSame(SoapVersion::Soap11, $version);

        $this->runRequest(new WsseMiddleware([$block]), $this->soapRequest(self::SOAP12_NS));
        static::assertSame(SoapVersion::Soap12, $version);
    }

    public function test_an_empty_outbound_list_leaves_the_request_untouched(): void
    {
        $request = $this->soapRequest(self::SOAP12_NS);

        [$sentRequest] = $this->runRequest(new WsseMiddleware(), $request);

        static::assertSame($request, $sentRequest);
    }

    public function test_an_empty_inbound_list_leaves_the_response_untouched(): void
    {
        $response = new Response(200, [], $this->soapEnvelope(self::SOAP12_NS));

        [, $returned] = $this->runRequest(
            new WsseMiddleware(),
            $this->soapRequest(self::SOAP12_NS),
            $response,
        );

        static::assertSame($response, $returned);
    }

    public function test_it_rejects_a_doctype_in_the_request(): void
    {
        $middleware = new WsseMiddleware([$this->versionCapturingBlock($ignored)]);
        $request = $this->soapRequest(self::SOAP12_NS, withDoctype: true);

        $this->expectException(DoctypeNotAllowedException::class);
        $middleware->handleRequest($request, $this->next($sentRequest), $this->first())->wait();
    }

    public function test_it_rejects_a_doctype_in_the_response(): void
    {
        $middleware = new WsseMiddleware([], [$this->versionCapturingBlock($ignored)]);
        $response = new Response(200, [], $this->soapEnvelope(self::SOAP12_NS, withDoctype: true));

        $this->expectException(DoctypeNotAllowedException::class);
        $middleware->handleRequest(
            $this->soapRequest(self::SOAP12_NS),
            $this->next($sentRequest, $response),
            $this->first(),
        )->wait();
    }

    public function test_an_inbound_block_failure_propagates(): void
    {
        $block = new class implements InboundAction {
            public function __invoke(WsseContext $context): void
            {
                throw SecurityFault::inboundFailure();
            }
        };

        $middleware = new WsseMiddleware([], [$block]);

        $this->expectException(SecurityFault::class);
        $middleware->handleRequest(
            $this->soapRequest(self::SOAP12_NS),
            $this->next($sentRequest, new Response(200, [], $this->soapEnvelope(self::SOAP12_NS))),
            $this->first(),
        )->wait();
    }

    public function test_an_outbound_block_failure_propagates(): void
    {
        $failure = new RuntimeException('outbound block failed');
        $block = new class($failure) implements OutboundAction {
            public function __construct(private readonly RuntimeException $failure)
            {
            }

            public function __invoke(WsseContext $context): void
            {
                throw $this->failure;
            }
        };

        // Outbound runs synchronously before the next handler, so the failure leaves handleRequest directly.
        $this->expectExceptionObject($failure);
        (new WsseMiddleware([$block]))->handleRequest(
            $this->soapRequest(self::SOAP12_NS),
            $this->next($sentRequest),
            $this->first(),
        );
    }

    public function test_it_returns_the_response_from_the_next_handler(): void
    {
        $response = new Response(204);

        [, $returned] = $this->runRequest(
            new WsseMiddleware(),
            $this->soapRequest(self::SOAP12_NS),
            $response,
        );

        static::assertSame($response, $returned);
    }

    public function test_it_adds_a_real_timestamp_to_the_outgoing_request(): void
    {
        $middleware = new WsseMiddleware([new Outbound\Timestamp()]);
        $request = $this->soapRequest(self::SOAP12_NS, withSecurityHeader: true);

        [$sentRequest] = $this->runRequest($middleware, $request);

        $body = (string) $sentRequest->getBody();
        static::assertStringContainsString('Timestamp', $body);
        static::assertStringContainsString('Created', $body);
        static::assertStringContainsString('Expires', $body);
    }

    /**
     * @param-out SoapVersion|null $captured
     */
    private function versionCapturingBlock(?SoapVersion &$captured): OutboundAction
    {
        return new class($captured) implements OutboundAction {
            public function __construct(private ?SoapVersion &$captured)
            {
            }

            public function __invoke(WsseContext $context): void
            {
                $this->captured = $context->soapVersion();
            }
        };
    }

    /**
     * @param-out RequestInterface $sentRequest
     * @return array{0: RequestInterface, 1: ResponseInterface}
     */
    private function runRequest(
        WsseMiddleware $middleware,
        RequestInterface $request,
        ?ResponseInterface $response = null,
    ): array {
        $response ??= new Response(200);
        $promise = $middleware->handleRequest($request, $this->next($sentRequest, $response), $this->first());

        return [$sentRequest, $promise->wait()];
    }

    /**
     * @param-out RequestInterface $sentRequest
     * @return callable(RequestInterface): Promise
     */
    private function next(?RequestInterface &$sentRequest, ?ResponseInterface $response = null): callable
    {
        $response ??= new Response(200);

        return static function (RequestInterface $request) use (&$sentRequest, $response): Promise {
            $sentRequest = $request;

            return new FulfilledPromise($response);
        };
    }

    /**
     * @return callable(RequestInterface): Promise
     */
    private function first(): callable
    {
        return static fn (RequestInterface $request): Promise => new FulfilledPromise(new Response(200));
    }

    private function soapRequest(
        string $namespace,
        bool $withDoctype = false,
        bool $withSecurityHeader = false,
    ): RequestInterface {
        return new Request(
            'POST',
            'https://example.org/service',
            ['SOAPAction' => 'urn:action'],
            $this->soapEnvelope($namespace, $withDoctype, $withSecurityHeader),
        );
    }

    private function soapEnvelope(
        string $namespace,
        bool $withDoctype = false,
        bool $withSecurityHeader = false,
    ): string {
        $doctype = $withDoctype ? '<!DOCTYPE Envelope>' : '';
        $header = $withSecurityHeader
            ? '<soap:Header><wsse:Security xmlns:wsse="'.self::WSSE_NS.'" xmlns:wsu="'.self::WSU_NS.'"></wsse:Security></soap:Header>'
            : '';

        return '<?xml version="1.0"?>'.$doctype
            .'<soap:Envelope xmlns:soap="'.$namespace.'">'.$header.'<soap:Body></soap:Body></soap:Envelope>';
    }
}
