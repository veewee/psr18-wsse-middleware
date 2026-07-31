# WsaMiddleware

[← Back to the deep dives](../README.md#deep-dives)

If your server expects WS-Addressing headers, add the WSA middleware. It is one configurable middleware that
covers both addressing versions, and it defaults to the W3C 2005/08 namespace.

```php
use Http\Client\Common\PluginClient;
use Soap\Psr18Transport\Psr18Transport;
use Soap\Psr18WsseMiddleware\WsaMiddleware;
use Soap\Psr18WsseMiddleware\Wsa\WsaNamespace;
use Soap\Psr18WsseMiddleware\Wsa\WsaOptions;

$transport = Psr18Transport::createForClient(
    new PluginClient($yourPsr18Client, [
        new WsaMiddleware(),
        // Or pick the addressing version explicitly:
        // new WsaMiddleware(new WsaOptions(WsaNamespace::Submission200408)),
        // Or set a non-anonymous ReplyTo address:
        // new WsaMiddleware(new WsaOptions(replyTo: 'https://your-app.example/reply')),
        // Or send faults somewhere other than the reply address:
        // new WsaMiddleware(new WsaOptions(faultTo: 'https://your-app.example/faults')),
    ])
);
```

Everything is configured through `WsaOptions`. Every property is optional, because each one has a sensible
answer without configuration: the default `new WsaOptions()` produces the headers a service expects:

- `WsaNamespace $namespace = WsaNamespace::W3c200508`: the addressing version. `WsaNamespace::W3c200508`
  (default) is the W3C 2005/08 namespace; `WsaNamespace::Submission200408` is the older 2004/08 submission
  namespace.
- `?string $action = null`: the `wsa:Action`. Default `null`, which uses the request's `SOAPAction`.
- `?string $to = null`: the `wsa:To`. Default `null`, which uses the request URI.
- `?string $replyTo = null`: the `wsa:ReplyTo` address. Default `null`, which uses the version's
  anonymous URI.
- `?string $from = null`: the `wsa:From` address. Default `null`, which omits the header.
- `?string $faultTo = null`: the `wsa:FaultTo` address, where the service sends a fault instead of to
  `ReplyTo`. Default `null`, which omits the header so faults follow `ReplyTo`.

`wsa:MessageID` is always freshly generated and is not configurable: the receiver echoes it back in
`wsa:RelatesTo` to correlate the reply, and a reused value would break that correlation. `wsa:RelatesTo`
itself is a reply property, so it is not an outbound option; `WsaHeader::withRelatesTo()` remains available
if you build a header directly.

It fills in `Action` (from the SOAP action), `To` (from the request URI), a generated `MessageID`, and
`ReplyTo`.

