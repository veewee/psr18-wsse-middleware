<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware;

use Http\Client\Common\Plugin;
use Http\Promise\Promise;
use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Soap\Psr18Transport\Xml\XmlMessageManipulator;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\PeerReportedFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\InboundAction;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\ExchangeKeys;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\OutboundAction;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator\Fault;
use Throwable;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Configurator\disallow_doctype;

/**
 * Applies WS-Security to a SOAP exchange: the outbound blocks write their tokens into the request and
 * the inbound blocks process the response, each over the same per-message document mutated in place.
 * A direction is only parsed when it has blocks, and every parse rejects a DOCTYPE before any block
 * runs. An outbound failure propagates to the caller as it is. An inbound one does too, unless the response
 * is also a SOAP fault, in which case what the peer stated is chained into the refusal for the operator log.
 * The one step that runs before the blocks and reads response-supplied content, deriving the SOAP version,
 * joins the inbound blocks in failing uniformly rather than naming what it found.
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
        // One bag per exchange, shared by both directions and by nothing else. A response is verified and
        // decrypted against a key its own request established; a bag living any longer would let it verify
        // against a key from another exchange, which is replay.
        $keys = new ExchangeKeys();

        if ($this->outbound !== []) {
            $request = $this->applyOutbound($request, $keys);
        }

        return $next($request)->then(
            fn (ResponseInterface $response): ResponseInterface =>
                $this->inbound === [] ? $response : $this->applyInbound($response, $keys),
        );
    }

    private function applyOutbound(RequestInterface $request, ExchangeKeys $keys): RequestInterface
    {
        // Outbound the envelope is the caller's own, so an unusable one is reported for what it is: naming
        // what was wrong with it is the whole value of the exception to the only person who can fix it.
        return $this->secure($request, SoapVersion::fromDocument(...), function (WsseContext $context): void {
            foreach ($this->outbound as $block) {
                $block($context);
            }
        }, $keys);
    }

    private function applyInbound(ResponseInterface $response, ExchangeKeys $keys): ResponseInterface
    {
        return $this->secure($response, self::inboundSoapVersion(...), function (WsseContext $context): void {
            try {
                foreach ($this->inbound as $block) {
                    $block($context);
                }
            } catch (Throwable $failure) {
                throw self::withWhatThePeerReported($context, $failure);
            }
        }, $keys);
    }

    /**
     * A response that failed its inbound checks and is *also* a SOAP fault gets what the peer stated chained
     * into the refusal, because the uniform failure otherwise leaves an operator unable to see that the server
     * had answered "invalid credentials" all along.
     *
     * The failure is only re-wrapped when there is something to add. A response that is not a fault propagates
     * the block's own exception untouched, so the common path keeps the exact object and chain it had.
     */
    private static function withWhatThePeerReported(WsseContext $context, Throwable $failure): Throwable
    {
        $reported = (new Fault())->locate($context->document(), $context->soapVersion());
        if ($reported === null) {
            return $failure;
        }

        // What reaches the caller stays the one constant message, so nothing the peer wrote into its fault
        // can vary it. The peer's own words sit one link further down, where only a log follows them.
        return SecurityFault::inboundFailure(PeerReportedFault::describing($reported, $failure));
    }

    /**
     * @template T of MessageInterface
     * @param T $message
     * @param callable(Document): SoapVersion $version
     * @param callable(WsseContext): void $run
     * @return T
     */
    private function secure(
        MessageInterface $message,
        callable $version,
        callable $run,
        ExchangeKeys $keys,
    ): MessageInterface {
        return (new XmlMessageManipulator())(
            $message,
            function (Document $document) use ($version, $run, $keys): void {
                $document->manipulate(disallow_doctype());
                $run(new WsseContext($document, $version($document), $this->profile, $keys));
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
