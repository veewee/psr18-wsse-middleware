<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware;

use Http\Client\Common\Plugin;
use Http\Promise\Promise;
use Psr\Http\Message\RequestInterface;
use Soap\Psr18Transport\HttpBinding\SoapActionDetector;
use Soap\Psr18Transport\Xml\XmlMessageManipulator;
use Soap\Psr18WsseMiddleware\Wsa\MessageId;
use Soap\Psr18WsseMiddleware\Wsa\WsaHeader;
use Soap\Psr18WsseMiddleware\Wsa\WsaOptions;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Configurator\disallow_doctype;

/**
 * Adds WS-Addressing headers (Action / To / MessageID / ReplyTo, and optionally From / FaultTo) to the
 * outgoing SOAP request. Everything is configured through WsaOptions, which also carries the addressing
 * version; the default instance derives every property from the request.
 */
final class WsaMiddleware implements Plugin
{
    public function __construct(
        private readonly WsaOptions $options = new WsaOptions(),
    ) {
    }

    public function handleRequest(RequestInterface $request, callable $next, callable $first): Promise
    {
        $request = (new XmlMessageManipulator())(
            $request,
            function (Document $document) use ($request): void {
                $document->manipulate(disallow_doctype());

                $this->header($request)->appendTo($document);
            },
        );

        return $next($request);
    }

    /**
     * The configured properties, with each unset one filled from the request. A fresh MessageID is minted per
     * message so the receiver's RelatesTo correlates exactly one reply.
     */
    private function header(RequestInterface $request): WsaHeader
    {
        $options = $this->options;

        $header = WsaHeader::create($options->namespace)
            ->withAction($options->action ?? SoapActionDetector::detectFromRequest($request))
            ->withTo($options->to ?? (string) $request->getUri())
            ->withMessageId(MessageId::generate())
            ->withReplyTo($options->replyTo ?? $options->namespace->anonymousUri());

        if ($options->from !== null) {
            $header = $header->withFrom($options->from);
        }

        if ($options->faultTo !== null) {
            $header = $header->withFaultTo($options->faultTo);
        }

        return $header;
    }
}
