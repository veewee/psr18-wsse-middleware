<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware;

use Http\Client\Common\Plugin;
use Http\Promise\Promise;
use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Soap\Psr18Transport\Xml\XmlMessageManipulator;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\InboundAction;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\OutboundAction;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Configurator\disallow_doctype;

/**
 * Applies WS-Security to a SOAP exchange: the outbound blocks write their tokens into the request and
 * the inbound blocks process the response, each over the same per-message document mutated in place.
 * A direction is only parsed when it has blocks, and every parse rejects a DOCTYPE before any block
 * runs. Block exceptions are not caught here; an outbound or inbound failure propagates to the caller. The
 * one step that runs before the blocks and reads response-supplied content, deriving the SOAP version, joins
 * the inbound blocks in failing uniformly rather than naming what it found.
 */
final class WsseMiddleware implements Plugin
{
    /**
     * @param list<OutboundAction> $outbound
     * @param list<InboundAction>  $inbound
     */
    public function __construct(
        private readonly SecurityProfile $profile,
        private readonly array $outbound = [],
        private readonly array $inbound = [],
    ) {
    }

    public function handleRequest(RequestInterface $request, callable $next, callable $first): Promise
    {
        if ($this->outbound !== []) {
            $request = $this->applyOutbound($request);
        }

        return $next($request)->then(
            fn (ResponseInterface $response): ResponseInterface =>
                $this->inbound === [] ? $response : $this->applyInbound($response),
        );
    }

    private function applyOutbound(RequestInterface $request): RequestInterface
    {
        // Outbound the envelope is the caller's own, so an unusable one is reported for what it is: naming
        // what was wrong with it is the whole value of the exception to the only person who can fix it.
        return $this->secure($request, SoapVersion::fromDocument(...), function (WsseContext $context): void {
            foreach ($this->outbound as $block) {
                $block($context);
            }
        });
    }

    private function applyInbound(ResponseInterface $response): ResponseInterface
    {
        return $this->secure($response, self::inboundSoapVersion(...), function (WsseContext $context): void {
            foreach ($this->inbound as $block) {
                $block($context);
            }
        });
    }

    /**
     * @template T of MessageInterface
     * @param T $message
     * @param callable(Document): SoapVersion $version
     * @param callable(WsseContext): void $run
     * @return T
     */
    private function secure(MessageInterface $message, callable $version, callable $run): MessageInterface
    {
        return (new XmlMessageManipulator())(
            $message,
            function (Document $document) use ($version, $run): void {
                $document->manipulate(disallow_doctype());
                $run(new WsseContext($document, $version($document), $this->profile));
            },
        );
    }

    /**
     * The version is derived before any block runs, so it sits outside every block's own uniform failure while
     * reading a namespace the response chose. Reporting an unrecognised one on its own would tell a peer that
     * this rejection was the version check rather than a signature, a timestamp or a trust decision, so it
     * collapses to the same fault the blocks produce. The reason stays chained, for the operator log only.
     *
     * @throws SecurityFault
     */
    private static function inboundSoapVersion(Document $document): SoapVersion
    {
        try {
            return SoapVersion::fromDocument($document);
        } catch (WsseHeaderException $exception) {
            throw SecurityFault::inboundFailure($exception);
        }
    }
}
