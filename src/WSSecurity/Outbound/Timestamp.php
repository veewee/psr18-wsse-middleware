<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

use DateTimeImmutable;
use DateTimeZone;
use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Wsse\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\Wsse\WsuIdMinter;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespace;
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
    private const TIME_FORMAT = 'Y-m-d\TH:i:s.v\Z';

    /**
     * @param positive-int $ttl seconds until expiry
     */
    public function __construct(
        private readonly int $ttl = 300,
    ) {
    }

    public function __invoke(WsseContext $context): void
    {
        $document = $context->document();
        $minter = new WsuIdMinter();

        $created = new DateTimeImmutable('now', new DateTimeZone('UTC'));
        $expires = $created->modify('+'.$this->ttl.' seconds');

        $header = SecurityHeader::locateOrCreate($document, $context->soapVersion());
        $header->appendChildren($this->build($document, $minter, $created, $expires));
    }

    /**
     * @return callable(Element): Element
     */
    private function build(
        Document $document,
        WsuIdMinter $minter,
        DateTimeImmutable $created,
        DateTimeImmutable $expires,
    ): callable {
        $build = namespaced_element(
            WsseNamespace::Wsu->value,
            WsseNamespace::Wsu->qualify('Timestamp'),
            children(
                namespaced_element(WsseNamespace::Wsu->value, WsseNamespace::Wsu->qualify('Created'), value($created->format(self::TIME_FORMAT))),
                namespaced_element(WsseNamespace::Wsu->value, WsseNamespace::Wsu->qualify('Expires'), value($expires->format(self::TIME_FORMAT))),
            ),
        );

        return static function (Element $parent) use ($build, $minter, $document): Element {
            $element = $build($parent);
            $minter->mint($element, $document);

            return $element;
        };
    }
}
