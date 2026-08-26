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
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\PeerReportedFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\InboundAction;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\OutboundAction;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WsseMiddleware;
use VeeWee\Xml\Exception\DoctypeNotAllowedException;
use VeeWee\Xml\Exception\RuntimeException as XmlRuntimeException;
use function VeeWee\Xml\Dom\Builder\element;

final class WsseMiddlewareTest extends TestCase
{
    private const SOAP11_NS = 'http://schemas.xmlsoap.org/soap/envelope/';
    private const SOAP12_NS = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSSE_NS = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const WSU_NS = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';

    public function test_it_is_a_middleware(): void
    {
        static::assertInstanceOf(Plugin::class, new WsseMiddleware(new SecurityProfile()));
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
            new WsseMiddleware(new SecurityProfile(), [$block]),
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
            new WsseMiddleware(new SecurityProfile(), [], [$block]),
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

        $this->runRequest(new WsseMiddleware(new SecurityProfile(), [$block]), $this->soapRequest(self::SOAP11_NS));
        static::assertSame(SoapVersion::Soap11, $version);

        $this->runRequest(new WsseMiddleware(new SecurityProfile(), [$block]), $this->soapRequest(self::SOAP12_NS));
        static::assertSame(SoapVersion::Soap12, $version);
    }

    public function test_an_empty_outbound_list_leaves_the_request_untouched(): void
    {
        $request = $this->soapRequest(self::SOAP12_NS);

        [$sentRequest] = $this->runRequest(new WsseMiddleware(new SecurityProfile()), $request);

        static::assertSame($request, $sentRequest);
    }

    public function test_an_empty_inbound_list_leaves_the_response_untouched(): void
    {
        $response = new Response(200, [], $this->soapEnvelope(self::SOAP12_NS));

        [, $returned] = $this->runRequest(
            new WsseMiddleware(new SecurityProfile()),
            $this->soapRequest(self::SOAP12_NS),
            $response,
        );

        static::assertSame($response, $returned);
    }

    public function test_it_rejects_a_doctype_in_the_request(): void
    {
        $middleware = new WsseMiddleware(new SecurityProfile(), [$this->versionCapturingBlock($ignored)]);
        $request = $this->soapRequest(self::SOAP12_NS, withDoctype: true);

        $this->expectException(DoctypeNotAllowedException::class);
        $middleware->handleRequest($request, $this->next($sentRequest), $this->first())->wait();
    }

    public function test_it_rejects_a_doctype_in_the_response(): void
    {
        $middleware = new WsseMiddleware(new SecurityProfile(), [], [$this->versionCapturingBlock($ignored)]);
        $response = new Response(200, [], $this->soapEnvelope(self::SOAP12_NS, withDoctype: true));

        $this->expectException(DoctypeNotAllowedException::class);
        $middleware->handleRequest(
            $this->soapRequest(self::SOAP12_NS),
            $this->next($sentRequest, $response),
            $this->first(),
        )->wait();
    }

    /**
     * SECURITY: the middleware sets no message-size cap of its own and instead relies on the parser's
     * default limits, which means it must never ask for the parse mode that lifts them. This pins the
     * reliance: an inbound response nested past the parser's depth limit is refused, not parsed.
     */
    public function test_it_refuses_a_response_nested_past_the_parser_depth_limit(): void
    {
        $depth = 300;
        $body = '<soap:Envelope xmlns:soap="'.self::SOAP12_NS.'"><soap:Body>'
            .str_repeat('<a>', $depth).'x'.str_repeat('</a>', $depth)
            .'</soap:Body></soap:Envelope>';
        $middleware = new WsseMiddleware(new SecurityProfile(), [], [$this->versionCapturingBlock($ignored)]);

        $this->expectException(XmlRuntimeException::class);
        $middleware->handleRequest(
            $this->soapRequest(self::SOAP12_NS),
            $this->next($sentRequest, new Response(200, [], $body)),
            $this->first(),
        )->wait();
    }

    public function test_it_parses_a_response_within_the_parser_depth_limit(): void
    {
        $depth = 200;
        $body = '<soap:Envelope xmlns:soap="'.self::SOAP12_NS.'"><soap:Body>'
            .str_repeat('<a>', $depth).'x'.str_repeat('</a>', $depth)
            .'</soap:Body></soap:Envelope>';
        $version = null;
        $middleware = new WsseMiddleware(new SecurityProfile(), [], [$this->versionCapturingBlock($version)]);

        $middleware->handleRequest(
            $this->soapRequest(self::SOAP12_NS),
            $this->next($sentRequest, new Response(200, [], $body)),
            $this->first(),
        )->wait();

        static::assertSame(SoapVersion::Soap12, $version);
    }

    public function test_a_response_that_is_not_a_soap_envelope_fails_uniformly(): void
    {
        // The envelope namespace is response-supplied, and it is read before any block runs. Left alone it
        // reaches the caller as its own exception type carrying the namespace verbatim, which tells a peer that
        // this one rejection was the version check rather than any of the others.
        $middleware = new WsseMiddleware(new SecurityProfile(), [], [$this->versionCapturingBlock($ignored)]);
        $response = new Response(200, [], '<env:Envelope xmlns:env="urn:not-soap"><env:Body/></env:Envelope>');

        try {
            $middleware->handleRequest(
                $this->soapRequest(self::SOAP12_NS),
                $this->next($sentRequest, $response),
                $this->first(),
            )->wait();
        } catch (SecurityFault $fault) {
            static::assertSame('The inbound security header could not be processed.', $fault->getMessage());
            static::assertStringNotContainsString('urn:not-soap', $fault->getMessage());
            // The reason stays available to the operator and never to the peer.
            static::assertInstanceOf(WsseHeaderException::class, $fault->getPrevious());

            return;
        }

        static::fail('Expected a SecurityFault for a response that is not a SOAP envelope.');
    }

    public function test_a_request_that_is_not_a_soap_envelope_still_reports_the_reason(): void
    {
        // The other half: outbound the envelope is the caller's own, so collapsing the reason would only hide
        // a configuration mistake from the one person able to fix it.
        $middleware = new WsseMiddleware(new SecurityProfile(), [$this->versionCapturingBlock($ignored)]);
        $request = new Request(
            'POST',
            'https://example.org/service',
            ['SOAPAction' => 'urn:action'],
            '<env:Envelope xmlns:env="urn:not-soap"><env:Body/></env:Envelope>',
        );

        $this->expectException(WsseHeaderException::class);
        $this->expectExceptionMessage('urn:not-soap');
        $middleware->handleRequest($request, $this->next($sentRequest), $this->first())->wait();
    }

    public function test_an_inbound_block_failure_propagates(): void
    {
        $block = new class implements InboundAction {
            public function __invoke(WsseContext $context): void
            {
                throw SecurityFault::inboundFailure();
            }
        };

        $middleware = new WsseMiddleware(new SecurityProfile(), [], [$block]);

        $this->expectException(SecurityFault::class);
        $middleware->handleRequest(
            $this->soapRequest(self::SOAP12_NS),
            $this->next($sentRequest, new Response(200, [], $this->soapEnvelope(self::SOAP12_NS))),
            $this->first(),
        )->wait();
    }

    public function test_an_inbound_failure_on_a_fault_response_chains_what_the_peer_reported(): void
    {
        $cause = SecurityFault::inboundFailure();
        $block = $this->throwingInboundBlock($cause);
        $middleware = new WsseMiddleware(new SecurityProfile(), [], [$block]);

        try {
            $middleware->handleRequest(
                $this->soapRequest(self::SOAP12_NS),
                $this->next($sentRequest, new Response(500, [], $this->soapFaultEnvelope(self::SOAP12_NS))),
                $this->first(),
            )->wait();
        } catch (SecurityFault $fault) {
            // The message is the no-oracle guarantee and must not move, whatever the peer put in its fault.
            static::assertSame('The inbound security header could not be processed.', $fault->getMessage());

            $reported = $fault->getPrevious();
            static::assertInstanceOf(PeerReportedFault::class, $reported);
            static::assertStringContainsString('soap:Sender', $reported->getMessage());
            static::assertStringContainsString('Invalid security token', $reported->getMessage());

            // The original cause stays reachable behind it, so nothing an operator had before is lost.
            static::assertSame($cause, $reported->getPrevious());

            return;
        }

        static::fail('Expected a SecurityFault for a failing inbound block.');
    }

    public function test_an_inbound_failure_on_a_response_that_is_not_a_fault_is_left_exactly_as_it_was(): void
    {
        $cause = SecurityFault::inboundFailure();
        $block = $this->throwingInboundBlock($cause);
        $middleware = new WsseMiddleware(new SecurityProfile(), [], [$block]);

        try {
            $middleware->handleRequest(
                $this->soapRequest(self::SOAP12_NS),
                $this->next($sentRequest, new Response(200, [], $this->soapEnvelope(self::SOAP12_NS))),
                $this->first(),
            )->wait();
        } catch (SecurityFault $fault) {
            static::assertSame($cause, $fault);
            static::assertNull($fault->getPrevious());

            return;
        }

        static::fail('Expected a SecurityFault for a failing inbound block.');
    }

    public function test_it_reports_a_soap11_fault_a_peer_returned(): void
    {
        $block = $this->throwingInboundBlock(SecurityFault::inboundFailure());
        $middleware = new WsseMiddleware(new SecurityProfile(), [], [$block]);

        try {
            $middleware->handleRequest(
                $this->soapRequest(self::SOAP11_NS),
                $this->next($sentRequest, new Response(500, [], $this->soapFaultEnvelope(self::SOAP11_NS))),
                $this->first(),
            )->wait();
        } catch (SecurityFault $fault) {
            $reported = $fault->getPrevious();
            static::assertInstanceOf(PeerReportedFault::class, $reported);
            static::assertStringContainsString('soap:Client', $reported->getMessage());
            static::assertStringContainsString('Invalid security token', $reported->getMessage());

            return;
        }

        static::fail('Expected a SecurityFault for a failing inbound block.');
    }

    private function throwingInboundBlock(SecurityFault $cause): InboundAction
    {
        return new class($cause) implements InboundAction {
            public function __construct(private readonly SecurityFault $cause)
            {
            }

            public function __invoke(WsseContext $context): void
            {
                throw $this->cause;
            }
        };
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
        (new WsseMiddleware(new SecurityProfile(), [$block]))->handleRequest(
            $this->soapRequest(self::SOAP12_NS),
            $this->next($sentRequest),
            $this->first(),
        );
    }

    public function test_it_returns_the_response_from_the_next_handler(): void
    {
        $response = new Response(204);

        [, $returned] = $this->runRequest(
            new WsseMiddleware(new SecurityProfile()),
            $this->soapRequest(self::SOAP12_NS),
            $response,
        );

        static::assertSame($response, $returned);
    }

    public function test_it_adds_a_real_timestamp_to_the_outgoing_request(): void
    {
        $middleware = new WsseMiddleware(new SecurityProfile(), [new Outbound\Timestamp()]);
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

    private function soapFaultEnvelope(string $namespace): string
    {
        $fault = $namespace === self::SOAP11_NS
            ? '<soap:Fault><faultcode>soap:Client</faultcode>'
                .'<faultstring>Invalid security token</faultstring></soap:Fault>'
            : '<soap:Fault><soap:Code><soap:Value>soap:Sender</soap:Value></soap:Code>'
                .'<soap:Reason><soap:Text xml:lang="en">Invalid security token</soap:Text></soap:Reason>'
                .'</soap:Fault>';

        return '<?xml version="1.0"?><soap:Envelope xmlns:soap="'.$namespace.'">'
            .'<soap:Body>'.$fault.'</soap:Body></soap:Envelope>';
    }
}
