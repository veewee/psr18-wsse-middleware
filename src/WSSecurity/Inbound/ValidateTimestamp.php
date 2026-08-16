<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Inbound;

use Dom\Element;
use Psl\DateTime\Exception\ParserException;
use Psl\DateTime\Timestamp;
use Psl\DateTime\Timezone;
use Soap\Psr18WsseMiddleware\Clock\Clock;
use Soap\Psr18WsseMiddleware\Clock\SystemClock;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\WSSecurity\Validator\TimestampValidator;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespaces;
use Soap\Psr18WsseMiddleware\Xml\ChildElements;
use Soap\Psr18WsseMiddleware\Xml\ElementText;
use Throwable;

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
    // The instant shape a conforming peer writes, captured so the fraction can be normalised: date and time,
    // an optional fraction of any length, then the zone. Anchored at both ends because the Intl parser would
    // otherwise accept trailing characters after a valid prefix.
    private const INSTANT_SHAPE = '/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$/';

    // Every value reaching the parser carries a three-digit fraction. The numeric-offset pattern is tried
    // before the literal-Z one so an offset string is read with its true offset rather than being swallowed by
    // the more lenient literal-Z match.
    private const ACCEPTED_FORMATS = [
        "yyyy-MM-dd'T'HH:mm:ss.SSSxxx",
        "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'",
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
        $now = $this->now();
        $profile = $context->profile();

        $timestamp = $this->locateTimestamp($context);
        $created = $this->parseInstant($this->requireChildText($timestamp, 'Created'));
        $expires = $this->parseInstant($this->requireChildText($timestamp, 'Expires'));

        $this->validator->validate($now, $created, $expires, $profile->clockSkew(), $profile->timestampTtl());
    }

    /**
     * The clock is a replaceable seam, so a deployment can hand over one backed by a time service. Such a clock
     * raises types of its own on a timeout or a transport error, and left alone each reaches the caller
     * distinguishable from every other inbound refusal. The reason stays chained, for the operator log only.
     *
     * @throws SecurityFault
     */
    private function now(): Timestamp
    {
        try {
            return $this->clock->now();
        } catch (Throwable $exception) {
            throw SecurityFault::inboundFailure($exception);
        }
    }

    private function locateTimestamp(WsseContext $context): Element
    {
        try {
            $security = SecurityHeader::locate($context->document(), $context->soapVersion(), $context->profile()->actorOrRole());
        } catch (WsseHeaderException $exception) {
            throw SecurityFault::inboundFailure($exception);
        }

        if ($security === null) {
            throw SecurityFault::inboundFailure();
        }

        // Exactly one, so a second injected wsu:Timestamp cannot shadow the real one.
        return ChildElements::single($security, WsseNamespaces::Wsu, 'Timestamp')
            ?? throw SecurityFault::inboundFailure();
    }

    private function requireChildText(Element $timestamp, string $localName): string
    {
        // Exactly one, so a second injected wsu:Created/wsu:Expires cannot shadow the real one.
        $child = ChildElements::single($timestamp, WsseNamespaces::Wsu, $localName)
            ?? throw SecurityFault::inboundFailure();

        $text = ElementText::trimmed($child);
        if ($text === '') {
            throw SecurityFault::inboundFailure();
        }

        return $text;
    }

    private function parseInstant(string $value): Timestamp
    {
        // The underlying Intl parser is lenient and would accept trailing characters after a valid prefix,
        // so the exact instant shape is pinned here first; only a fully matching value reaches the parser.
        if (preg_match(self::INSTANT_SHAPE, $value, $parts) !== 1) {
            throw SecurityFault::inboundFailure();
        }

        // A conforming peer may write any number of fractional digits, and they disagree in practice, so the
        // fraction is rewritten to the millisecond form the parser reads. Dropping digits past the third
        // cannot change a verdict: the window is decided on whole seconds.
        $value = $parts[1].'.'.substr($parts[2].'000', 0, 3).$parts[3];

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
