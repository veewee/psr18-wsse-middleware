<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Inbound;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

use Psl\DateTime\SecondsStyle;
use Psl\DateTime\Timestamp;
use Psl\DateTime\Timezone;
use Soap\Psr18WsseMiddleware\Clock\Clock;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\ValidateTimestamp;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\ExchangeKeys;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use SoapTest\Psr18WsseMiddleware\Unit\Clock\FrozenClock;
use VeeWee\Xml\Dom\Document;

/**
 * The ValidateTimestamp block locates the single wsu:Timestamp, parses its Created and Expires, and runs the
 * freshness checks against an injected clock. These tests pin the clock so each boundary is exact and prove
 * the injected clock, not the system clock, drives the comparison.
 */
final class ValidateTimestampTest extends TestCase
{
    private const SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
    private const NOW = '2026-01-01T12:00:00Z';

    public function test_a_fresh_timestamp_is_accepted(): void
    {
        $now = $this->instant(self::NOW);
        $xml = $this->envelope(
            $this->timestamp($this->fmt($now), $this->fmt($now->plusSeconds(300))),
        );

        $this->block()($this->context($xml));

        // The same message past the freshness window is refused, so the acceptance above came from a real
        // check of the dates, not a silent pass.
        $this->expectException(SecurityFault::class);
        ((new ValidateTimestamp())->withClock($this->clock($now->plusSeconds(361))))($this->context($xml));
    }

    public function test_an_expired_timestamp_is_rejected(): void
    {
        $now = $this->instant(self::NOW);
        $context = $this->context($this->envelope(
            $this->timestamp($this->fmt($now->minusSeconds(300)), $this->fmt($now->minusSeconds(61))),
        ));

        $this->expectException(SecurityFault::class);
        $this->block()($context);
    }

    public function test_a_future_created_is_rejected(): void
    {
        $now = $this->instant(self::NOW);
        $created = $now->plusSeconds(61);
        $context = $this->context($this->envelope(
            $this->timestamp($this->fmt($created), $this->fmt($created->plusSeconds(300))),
        ));

        $this->expectException(SecurityFault::class);
        $this->block()($context);
    }

    public function test_a_missing_timestamp_is_rejected(): void
    {
        $context = $this->context($this->envelope(''));

        $this->expectException(SecurityFault::class);
        $this->block()($context);
    }

    public function test_a_duplicate_timestamp_is_rejected(): void
    {
        $now = $this->instant(self::NOW);
        $one = $this->timestamp($this->fmt($now), $this->fmt($now->plusSeconds(300)));
        $context = $this->context($this->envelope($one.$one));

        $this->expectException(SecurityFault::class);
        $this->block()($context);
    }

    public function test_a_timestamp_planted_outside_the_security_header_is_not_read(): void
    {
        // A fresh timestamp smuggled into the Body must not stand in for the missing real one.
        $now = $this->instant(self::NOW);
        $planted = '<wsse:Security xmlns:wsse="'.self::WSSE.'">'
            .$this->timestamp($this->fmt($now), $this->fmt($now->plusSeconds(300)))
            .'</wsse:Security>';
        $context = $this->context(
            '<soap:Envelope xmlns:soap="'.self::SOAP.'"><soap:Header/>'
            .'<soap:Body>'.$planted.'</soap:Body></soap:Envelope>',
        );

        $this->expectException(SecurityFault::class);
        $this->block()($context);
    }

    public function test_a_timestamp_in_another_roles_security_header_is_not_read(): void
    {
        // The intermediary's header is not ours; its timestamp cannot satisfy our freshness check.
        $now = $this->instant(self::NOW);
        $context = $this->context(
            '<soap:Envelope xmlns:soap="'.self::SOAP.'"><soap:Header>'
            .'<wsse:Security xmlns:wsse="'.self::WSSE.'" soap:role="urn:intermediary">'
            .$this->timestamp($this->fmt($now), $this->fmt($now->plusSeconds(300)))
            .'</wsse:Security>'
            .'</soap:Header><soap:Body><data>x</data></soap:Body></soap:Envelope>',
        );

        $this->expectException(SecurityFault::class);
        $this->block()($context);
    }

    public function test_a_missing_created_element_is_rejected(): void
    {
        $now = $this->instant(self::NOW);
        $expires = '<wsu:Expires>'.$this->fmt($now->plusSeconds(300)).'</wsu:Expires>';
        $created = '<wsu:Created>'.$this->fmt($now).'</wsu:Created>';

        $this->assertRefusedOnlyBecause(
            '<wsu:Timestamp xmlns:wsu="'.self::WSU.'">'.$expires.'</wsu:Timestamp>',
            '<wsu:Timestamp xmlns:wsu="'.self::WSU.'">'.$created.$expires.'</wsu:Timestamp>',
        );
    }

    public function test_a_missing_expires_element_is_rejected(): void
    {
        $now = $this->instant(self::NOW);
        $created = '<wsu:Created>'.$this->fmt($now).'</wsu:Created>';
        $expires = '<wsu:Expires>'.$this->fmt($now->plusSeconds(300)).'</wsu:Expires>';

        $this->assertRefusedOnlyBecause(
            '<wsu:Timestamp xmlns:wsu="'.self::WSU.'">'.$created.'</wsu:Timestamp>',
            '<wsu:Timestamp xmlns:wsu="'.self::WSU.'">'.$created.$expires.'</wsu:Timestamp>',
        );
    }

    public function test_a_duplicate_created_element_is_rejected(): void
    {
        $now = $this->instant(self::NOW);
        $created = '<wsu:Created>'.$this->fmt($now).'</wsu:Created>';
        $expires = '<wsu:Expires>'.$this->fmt($now->plusSeconds(300)).'</wsu:Expires>';

        $this->assertRefusedOnlyBecause(
            '<wsu:Timestamp xmlns:wsu="'.self::WSU.'">'.$created.$created.$expires.'</wsu:Timestamp>',
            '<wsu:Timestamp xmlns:wsu="'.self::WSU.'">'.$created.$expires.'</wsu:Timestamp>',
        );
    }

    public function test_an_unparseable_date_is_rejected(): void
    {
        $now = $this->instant(self::NOW);
        $context = $this->context($this->envelope(
            $this->timestamp('not-a-date', $this->fmt($now->plusSeconds(300))),
        ));

        $this->expectException(SecurityFault::class);
        $this->block()($context);
    }

    public function test_a_relative_string_is_not_accepted_as_a_date(): void
    {
        $now = $this->instant(self::NOW);
        $context = $this->context($this->envelope(
            $this->timestamp('now', $this->fmt($now->plusSeconds(300))),
        ));

        $this->expectException(SecurityFault::class);
        $this->block()($context);
    }

    public function test_a_valid_prefix_with_trailing_garbage_is_rejected(): void
    {
        $now = $this->instant(self::NOW);
        $context = $this->context($this->envelope(
            $this->timestamp($this->fmt($now).' trailing-garbage', $this->fmt($now->plusSeconds(300))),
        ));

        $this->expectException(SecurityFault::class);
        $this->block()($context);
    }

    public function test_a_millisecond_precision_timestamp_parses(): void
    {
        $now = $this->instant(self::NOW);
        $xml = $this->envelope($this->timestamp(
            $this->fmt($now),
            $this->fmt($now->plusSeconds(300)),
        ));

        $this->block()($this->context($xml));

        $this->assertTheDatesWereRead($xml, $now);
    }

    public function test_a_second_precision_timestamp_parses(): void
    {
        $now = $this->instant(self::NOW);
        $xml = $this->envelope($this->timestamp(
            $this->fmtSeconds($now),
            $this->fmtSeconds($now->plusSeconds(300)),
        ));

        $this->block()($this->context($xml));

        $this->assertTheDatesWereRead($xml, $now);
    }

    public function test_a_numeric_offset_timestamp_parses(): void
    {
        $now = $this->instant(self::NOW);
        $xml = $this->envelope($this->timestamp(
            $this->fmtOffset($now),
            $this->fmtOffset($now->plusSeconds(300)),
        ));

        $this->block()($this->context($xml));

        $this->assertTheDatesWereRead($xml, $now);
    }

    public function test_a_millisecond_offset_timestamp_parses(): void
    {
        $now = $this->instant(self::NOW);
        $xml = $this->envelope($this->timestamp(
            $this->fmtMilliOffset($now),
            $this->fmtMilliOffset($now->plusSeconds(300)),
        ));

        $this->block()($this->context($xml));

        $this->assertTheDatesWereRead($xml, $now);
    }

    /**
     * xs:dateTime puts no bound on the fractional digits, and peers differ: WSS4J emits three, .NET's
     * round-trip form up to seven, and a conforming peer may emit one or two. Accepting only exactly three
     * refused legal timestamps, which failed the whole exchange behind an intentionally uninformative fault.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function fractionalDigits(): iterable
    {
        yield 'one digit' => ['.1'];
        yield 'two digits' => ['.12'];
        yield 'three digits, what WSS4J emits' => ['.123'];
        yield 'six digits' => ['.123456'];
        yield 'seven digits, the .NET round-trip form' => ['.1234567'];
        yield 'nine digits' => ['.123456789'];
    }

    /**
     * Accepted, and read as the instant it names. The assertion is a one-second boundary either side of Expires,
     * so a fraction leaking into the seconds field (123456 read as milliseconds would move the instant by two
     * minutes) shows up as a flipped verdict rather than passing unnoticed.
     */
    #[DataProvider('fractionalDigits')]
    public function test_any_legal_fractional_precision_parses_to_the_instant_it_names(string $fraction): void
    {
        $xml = $this->envelope($this->timestamp(
            '2026-01-01T12:00:00'.$fraction.'Z',
            '2026-01-01T12:05:00'.$fraction.'Z',
        ));
        $exact = $this->context($xml, new SecurityProfile(clockSkew: 0));

        // On the expiry second the message is still fresh.
        ((new ValidateTimestamp())->withClock($this->clock($this->instant('2026-01-01T12:05:00Z'))))($exact);

        // One second past it, it is not.
        $this->expectException(SecurityFault::class);
        ((new ValidateTimestamp())->withClock($this->clock($this->instant('2026-01-01T12:05:01Z'))))(
            $this->context($xml, new SecurityProfile(clockSkew: 0)),
        );
    }

    public function test_a_fractional_part_with_no_digits_is_rejected(): void
    {
        $xml = $this->envelope($this->timestamp('2026-01-01T12:00:00.Z', '2026-01-01T12:05:00.Z'));

        $this->expectException(SecurityFault::class);
        $this->block()($this->context($xml));
    }

    public function test_no_security_header_is_rejected(): void
    {
        $context = $this->context(
            '<soap:Envelope xmlns:soap="'.self::SOAP.'"><soap:Body><data>x</data></soap:Body></soap:Envelope>',
        );

        $this->expectException(SecurityFault::class);
        $this->block()($context);
    }

    public function test_a_custom_clock_skew_is_honoured(): void
    {
        $now = $this->instant(self::NOW);
        $xml = $this->envelope(
            $this->timestamp($this->fmt($now->minusSeconds(300)), $this->fmt($now->minusSeconds(90))),
        );

        ((new ValidateTimestamp())->withClock($this->clock($now)))($this->context($xml, new SecurityProfile(clockSkew: 120)));

        // One tick past the widened window the same message is refused, so the acceptance above sat inside
        // a live boundary at skew 120 rather than bypassing the check.
        $this->expectException(SecurityFault::class);
        ((new ValidateTimestamp())->withClock($this->clock($now->plusSeconds(31))))($this->context($xml, new SecurityProfile(clockSkew: 120)));
    }

    public function test_the_same_message_is_rejected_under_the_default_skew(): void
    {
        $now = $this->instant(self::NOW);
        $xml = $this->envelope(
            $this->timestamp($this->fmt($now->minusSeconds(300)), $this->fmt($now->minusSeconds(90))),
        );

        $this->expectException(SecurityFault::class);
        $this->block()($this->context($xml));
    }

    public function test_the_injected_clock_drives_now(): void
    {
        // The frozen instant is far from the real wall clock; an envelope fresh only at that instant must pass,
        // proving the system clock is never consulted.
        $frozen = $this->instant('2000-06-15T08:30:00Z');
        $xml = $this->envelope(
            $this->timestamp($this->fmt($frozen), $this->fmt($frozen->plusSeconds(300))),
        );

        ((new ValidateTimestamp())->withClock($this->clock($frozen)))($this->context($xml));

        // Moving only the injected clock refuses the same message: the injected clock alone drives "now".
        $this->expectException(SecurityFault::class);
        ((new ValidateTimestamp())->withClock($this->clock($frozen->plusSeconds(361))))($this->context($xml));
    }

    /**
     * The proof a format-parse acceptance was real: the same message must be refused once the clock passes
     * its freshness window, which can only happen if the dates were actually parsed and compared.
     */
    /**
     * Asserts a malformed Timestamp is refused AND that the same Timestamp with only the named defect repaired
     * is accepted.
     *
     * Every refusal in this block collapses to one SecurityFault with one message and, for the structural
     * paths, no chained cause, so asserting the type or the message cannot say which guard fired. A test that
     * only asserted the refusal would keep passing if a future edit made a different check fail on this input:
     * the branch under test would stop being exercised and its name would start lying. The repaired control is
     * what pins it, because it proves the defect named here is the only thing this input fails on.
     */
    private function assertRefusedOnlyBecause(string $malformedTimestamp, string $repairedTimestamp): void
    {
        try {
            $this->block()($this->context($this->envelope($malformedTimestamp)));
            static::fail('Expected the malformed timestamp to be refused.');
        } catch (SecurityFault) {
            // expected
        }

        $this->block()($this->context($this->envelope($repairedTimestamp)));
        static::assertTrue(true, 'the repaired timestamp is accepted, so the refusal above was the named defect');
    }

    private function assertTheDatesWereRead(string $xml, Timestamp $now): void
    {
        $this->expectException(SecurityFault::class);
        ((new ValidateTimestamp())->withClock($this->clock($now->plusSeconds(361))))($this->context($xml));
    }

    /**
     * The timestamp is read from the header addressed to us, so a profile naming an actor reads that actor's
     * header. The delta is the actor alone: the same two headers, and only which one the profile claims, decide
     * whether the stale timestamp or the fresh one is the one checked.
     */
    public function test_it_reads_the_timestamp_from_the_header_addressed_to_the_configured_actor(): void
    {
        $stale = '<wsu:Created>2020-01-01T00:00:00Z</wsu:Created><wsu:Expires>2020-01-01T00:05:00Z</wsu:Expires>';
        $fresh = '<wsu:Created>'.self::NOW.'</wsu:Created><wsu:Expires>2999-01-01T00:00:00Z</wsu:Expires>';
        $xml = '<soap:Envelope xmlns:soap="'.self::SOAP.'" xmlns:wsse="'.self::WSSE.'" xmlns:wsu="'.self::WSU.'">'
            .'<soap:Header>'
            .'<wsse:Security><wsu:Timestamp>'.$stale.'</wsu:Timestamp></wsse:Security>'
            .'<wsse:Security soap:role="urn:ours"><wsu:Timestamp>'.$fresh.'</wsu:Timestamp></wsse:Security>'
            .'</soap:Header><soap:Body/></soap:Envelope>';

        // Ours is the actor-targeted header, whose timestamp is fresh.
        $this->block()($this->context($xml, new SecurityProfile(actorOrRole: 'urn:ours')));
        $this->addToAssertionCount(1);

        // Without the actor the untargeted header is ours, and its timestamp is long expired.
        $this->expectException(SecurityFault::class);
        $this->block()($this->context($xml, new SecurityProfile()));
    }

    private function block(): ValidateTimestamp
    {
        return (new ValidateTimestamp())->withClock($this->clock($this->instant(self::NOW)));
    }

    private function clock(Timestamp $now): Clock
    {
        return new FrozenClock($now);
    }

    private function context(string $xml, ?SecurityProfile $profile = null): WsseContext
    {
        return new WsseContext(Document::fromXmlString($xml), SoapVersion::Soap12, $profile ?? new SecurityProfile(), new ExchangeKeys());
    }

    private function envelope(string $securityInner): string
    {
        return '<soap:Envelope xmlns:soap="'.self::SOAP.'">'
            .'<soap:Header>'
            .'<wsse:Security xmlns:wsse="'.self::WSSE.'">'.$securityInner.'</wsse:Security>'
            .'</soap:Header>'
            .'<soap:Body><data>x</data></soap:Body>'
            .'</soap:Envelope>';
    }

    private function timestamp(string $created, string $expires): string
    {
        return '<wsu:Timestamp xmlns:wsu="'.self::WSU.'">'
            .'<wsu:Created>'.$created.'</wsu:Created>'
            .'<wsu:Expires>'.$expires.'</wsu:Expires>'
            .'</wsu:Timestamp>';
    }

    private function instant(string $value): Timestamp
    {
        return Timestamp::parse($value, "yyyy-MM-dd'T'HH:mm:ss'Z'", Timezone::UTC);
    }

    private function fmt(Timestamp $instant): string
    {
        return $instant->toRfc3339(SecondsStyle::Milliseconds, useZ: true);
    }

    private function fmtSeconds(Timestamp $instant): string
    {
        return $instant->toRfc3339(SecondsStyle::Seconds, useZ: true);
    }

    private function fmtOffset(Timestamp $instant): string
    {
        return $instant->format("yyyy-MM-dd'T'HH:mm:ssxxx", Timezone::UTC);
    }

    private function fmtMilliOffset(Timestamp $instant): string
    {
        return $instant->format("yyyy-MM-dd'T'HH:mm:ss.SSSxxx", Timezone::UTC);
    }
}
