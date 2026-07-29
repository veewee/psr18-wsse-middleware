<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\Wsa;

/**
 * The WS-Addressing settings WsaMiddleware applies to every outgoing request: the addressing version plus
 * each message-addressing property the caller wants to fix rather than let the middleware derive.
 *
 * Every property is optional because every one of them has a sensible answer without configuration. A null
 * Action is detected from the SOAPAction of the request, a null To is the request URI, and a null ReplyTo is
 * the addressing version's anonymous URI: so the default instance produces exactly the headers a service
 * expects. From and FaultTo have no derived value and are simply omitted when null, since a message that
 * names neither is complete.
 *
 * RelatesTo is deliberately absent: it correlates a reply to a request, so it has no meaning on an outbound
 * request. WsaHeader still exposes it for a caller building a header directly.
 *
 * MessageID is always freshly generated rather than configurable, because the receiver echoes it back to
 * correlate the reply and a reused value would break that correlation.
 */
final readonly class WsaOptions
{
    public function __construct(
        public WsaNamespace $namespace = WsaNamespace::W3c200508,
        public ?string $action = null,
        public ?string $to = null,
        public ?string $replyTo = null,
        public ?string $from = null,
        public ?string $faultTo = null,
    ) {
    }
}
