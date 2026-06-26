<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Inbound;

use DateTimeImmutable;
use DateTimeZone;
use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Clock\Clock;
use Soap\Psr18WsseMiddleware\WSSecurity\Clock\SystemClock;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\Internal\Validator\TimestampValidator;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
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
    private const ACCEPTED_FORMATS = [
        'Y-m-d\TH:i:s.v\Z',
        'Y-m-d\TH:i:s\Z',
        'Y-m-d\TH:i:s.vP',
        'Y-m-d\TH:i:sP',
    ];

    public function __construct(
        private readonly SecurityProfile $profile = new SecurityProfile(),
        private readonly Clock $clock = new SystemClock(),
        private readonly TimestampValidator $validator = new TimestampValidator(),
    ) {
    }

    /**
     * @throws SecurityFault
     */
    public function __invoke(WsseContext $context): void
    {
        $now = $this->clock->now()->setTimezone(new DateTimeZone('UTC'));

        $timestamp = $this->locateTimestamp($context);
        $created = $this->parseInstant($this->requireChildText($timestamp, 'Created'));
        $expires = $this->parseInstant($this->requireChildText($timestamp, 'Expires'));

        $this->validator->validate($now, $created, $expires, $this->profile->clockSkew(), $this->profile->timestampTtl());
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
        $found = null;
        /** @var \Dom\Node $child */
        foreach ($timestamp->childNodes as $child) {
            if (!$child instanceof Element) {
                continue;
            }

            if ($child->localName !== $localName || $child->namespaceURI !== WsseNamespace::Wsu->value) {
                continue;
            }

            if ($found !== null) {
                throw SecurityFault::inboundFailure();
            }

            $found = $child;
        }

        if ($found === null) {
            throw SecurityFault::inboundFailure();
        }

        $text = trim((string) $found->textContent);
        if ($text === '') {
            throw SecurityFault::inboundFailure();
        }

        return $text;
    }

    private function parseInstant(string $value): DateTimeImmutable
    {
        $utc = new DateTimeZone('UTC');

        foreach (self::ACCEPTED_FORMATS as $format) {
            $parsed = DateTimeImmutable::createFromFormat($format, $value, $utc);
            if ($parsed === false) {
                continue;
            }

            $errors = DateTimeImmutable::getLastErrors();
            if ($errors === false || ($errors['warning_count'] === 0 && $errors['error_count'] === 0)) {
                return $parsed->setTimezone($utc);
            }
        }

        throw SecurityFault::inboundFailure();
    }
}
