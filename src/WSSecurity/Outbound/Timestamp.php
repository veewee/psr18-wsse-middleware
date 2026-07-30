<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

use Dom\Element;
use Psl\DateTime\SecondsStyle;
use Psl\DateTime\Timestamp as Instant;
use Soap\Psr18WsseMiddleware\Clock\Clock;
use Soap\Psr18WsseMiddleware\Clock\SystemClock;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespaces;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdMinter;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\children;
use function VeeWee\Xml\Dom\Builder\namespaced_element;
use function VeeWee\Xml\Dom\Builder\value;

/**
 * Adds a wsu:Timestamp to the Security header so the receiver can reject a replayed or stale message.
 * The token carries wsu:Created (the current UTC instant) and wsu:Expires (Created plus the configured
 * ttl). Both are emitted with millisecond precision, the form interop peers expect. A wsu:Id is minted
 * on the token so the Signature block can sign the timestamp by reference.
 */
final class Timestamp implements OutboundAction
{
    private Clock $clock;

    /**
     * @param positive-int|null $ttl seconds until expiry; null takes the window from the security profile, so
     *                               an operator narrowing it there narrows it in both directions
     */
    public function __construct(
        private readonly ?int $ttl = null,
    ) {
        $this->clock = new SystemClock();
    }

    public function withClock(Clock $clock): self
    {
        $clone = clone $this;
        $clone->clock = $clock;

        return $clone;
    }

    public function __invoke(WsseContext $context): void
    {
        $document = $context->document();
        $minter = (new WsuIdConvention())->minter();

        $created = $this->clock->now();
        $expires = $created->plusSeconds($this->ttl ?? $context->profile()->timestampTtl());

        $header = SecurityHeader::forContext($context);
        $header->appendChildren($this->build($document, $minter, $created, $expires));
    }

    /**
     * @return callable(Element): Element
     */
    private function build(
        Document $document,
        IdMinter $minter,
        Instant $created,
        Instant $expires,
    ): callable {
        $build = namespaced_element(
            WsseNamespaces::Wsu->value,
            WsseNamespaces::Wsu->qualify('Timestamp'),
            children(
                namespaced_element(WsseNamespaces::Wsu->value, WsseNamespaces::Wsu->qualify('Created'), value($this->wire($created))),
                namespaced_element(WsseNamespaces::Wsu->value, WsseNamespaces::Wsu->qualify('Expires'), value($this->wire($expires))),
            ),
        );

        return static function (Element $parent) use ($build, $minter, $document): Element {
            $element = $build($parent);
            $minter->mint($element, $document);

            return $element;
        };
    }

    /**
     * Renders the instant as ISO-8601 UTC with millisecond precision and a literal Z, the form interop peers
     * expect.
     */
    private function wire(Instant $instant): string
    {
        return $instant->toRfc3339(SecondsStyle::Milliseconds, useZ: true);
    }
}
