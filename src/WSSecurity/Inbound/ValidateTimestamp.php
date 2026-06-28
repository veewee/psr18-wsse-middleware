<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Inbound;

use Dom\Element;
use Psl\DateTime\Exception\ParserException;
use Psl\DateTime\Timestamp;
use Psl\DateTime\Timezone;
use Soap\Psr18WsseMiddleware\WSSecurity\Clock\Clock;
use Soap\Psr18WsseMiddleware\WSSecurity\Clock\SystemClock;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\Internal\Validator\TimestampValidator;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\ChildElements;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespace;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseXpath;

/**
 * Rejects a stale, future-dated, or replayed-window message before the application sees it. It locates the
 * single wsu:Timestamp in the Security header, reads its Created and Expires, and asserts the message is not
 * expired, not older than the configured maximum age, and not stamped in the future, each within the
 * configured clock skew.
 *
 * Dates are parsed strictly: only the exact instant formats a conforming peer emits are accepted, never a
 * relative string, so an attacker cannot smuggle a value that resolves to the current time. Every failure,
 * whether the timestamp is absent, duplicated, malformed, or simply out of the window, collapses to one
 * uniform SecurityFault carrying no detail of which step failed.
 */
final class ValidateTimestamp implements InboundAction
{
    // Numeric-offset patterns are tried before the literal-Z ones so an offset string is read with its true
    // offset rather than being swallowed by the more lenient literal-Z match.
    private const ACCEPTED_FORMATS = [
        "yyyy-MM-dd'T'HH:mm:ss.SSSxxx",
        "yyyy-MM-dd'T'HH:mm:ssxxx",
        "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'",
        "yyyy-MM-dd'T'HH:mm:ss'Z'",
    ];

    private Clock $clock;
    private readonly TimestampValidator $validator;

    public function __construct()
    {
        $this->clock = new SystemClock();
        $this->validator = new TimestampValidator();
    }

    public function withClock(Clock $clock): self
    {
        $clone = clone $this;
        $clone->clock = $clock;

        return $clone;
    }

    /**
     * @throws SecurityFault
     */
    public function __invoke(WsseContext $context): void
    {
        $now = $this->clock->now();
        $profile = $context->profile();

        $timestamp = $this->locateTimestamp($context);
        $created = $this->parseInstant($this->requireChildText($timestamp, 'Created'));
        $expires = $this->parseInstant($this->requireChildText($timestamp, 'Expires'));

        $this->validator->validate($now, $created, $expires, $profile->clockSkew(), $profile->timestampTtl());
    }

    private function locateTimestamp(WsseContext $context): Element
    {
        $document = $context->document();
        $timestamps = $document
            ->xpath(new WsseXpath($document))
            ->query(
                '//'.WsseNamespace::Wsse->qualify('Security').'/'.WsseNamespace::Wsu->qualify('Timestamp'),
            )
            ->expectAllOfType(Element::class);

        if ($timestamps->count() !== 1) {
            throw SecurityFault::inboundFailure();
        }

        return $timestamps->expectSingle();
    }

    private function requireChildText(Element $timestamp, string $localName): string
    {
        // Exactly one, so a second injected wsu:Created/wsu:Expires cannot shadow the real one.
        $matches = ChildElements::named($timestamp, WsseNamespace::Wsu, $localName);
        if (count($matches) !== 1) {
            throw SecurityFault::inboundFailure();
        }

        $text = trim((string) $matches[0]->textContent);
        if ($text === '') {
            throw SecurityFault::inboundFailure();
        }

        return $text;
    }

    private function parseInstant(string $value): Timestamp
    {
        // The underlying Intl parser is lenient and would accept trailing characters after a valid prefix,
        // so the exact instant shape is pinned here first; only a fully matching value reaches the parser.
        if (preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?(?:Z|[+-]\d{2}:\d{2})$/', $value) !== 1) {
            throw SecurityFault::inboundFailure();
        }

        foreach (self::ACCEPTED_FORMATS as $format) {
            try {
                return Timestamp::parse($value, $format, Timezone::UTC);
            } catch (ParserException) {
                continue;
            }
        }

        throw SecurityFault::inboundFailure();
    }
}
