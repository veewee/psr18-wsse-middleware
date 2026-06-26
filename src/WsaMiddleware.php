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
use Soap\Psr18WsseMiddleware\Wsa\WsaNamespace;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Configurator\disallow_doctype;

/**
 * Adds WS-Addressing headers (Action / To / MessageID / ReplyTo) to the outgoing SOAP request.
 * Configurable for either addressing version; defaults to W3C 2005/08.
 */
final class WsaMiddleware implements Plugin
{
    public function __construct(
        private readonly WsaNamespace $namespace = WsaNamespace::W3c200508,
        private readonly ?string $replyToAddress = null,
    ) {
    }

    public function handleRequest(RequestInterface $request, callable $next, callable $first): Promise
    {
        $request = (new XmlMessageManipulator())(
            $request,
            function (Document $document) use ($request): void {
                $document->manipulate(disallow_doctype());

                WsaHeader::create($this->namespace)
                    ->withAction(SoapActionDetector::detectFromRequest($request))
                    ->withTo((string) $request->getUri())
                    ->withMessageId(MessageId::generate())
                    ->withReplyTo($this->replyToAddress ?? $this->namespace->anonymousUri())
                    ->appendTo($document);
            },
        );

        return $next($request);
    }
}
