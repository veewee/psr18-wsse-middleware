<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Inbound;

use PHPUnit\Framework\TestCase;

use Psl\DateTime\SecondsStyle;
use Psl\DateTime\Timestamp;
use Psl\DateTime\Timezone;
use Soap\Psr18WsseMiddleware\Clock\Clock;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\ValidateTimestamp;
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
        $context = $this->context($this->envelope(
            $this->timestamp($this->fmt($now), $this->fmt($now->plusSeconds(300))),
        ));

        $this->expectNotToPerformAssertions();
        $this->block()($context);
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
        $context = $this->context($this->envelope(
            '<wsu:Timestamp xmlns:wsu="'.self::WSU.'"><wsu:Expires>'.$this->fmt($now->plusSeconds(300)).'</wsu:Expires></wsu:Timestamp>',
        ));

        $this->expectException(SecurityFault::class);
        $this->block()($context);
    }

    public function test_a_missing_expires_element_is_rejected(): void
    {
        $now = $this->instant(self::NOW);
        $context = $this->context($this->envelope(
            '<wsu:Timestamp xmlns:wsu="'.self::WSU.'"><wsu:Created>'.$this->fmt($now).'</wsu:Created></wsu:Timestamp>',
        ));

        $this->expectException(SecurityFault::class);
        $this->block()($context);
    }

    public function test_a_duplicate_created_element_is_rejected(): void
    {
        $now = $this->instant(self::NOW);
        $created = '<wsu:Created>'.$this->fmt($now).'</wsu:Created>';
        $context = $this->context($this->envelope(
            '<wsu:Timestamp xmlns:wsu="'.self::WSU.'">'.$created.$created.'<wsu:Expires>'.$this->fmt($now->plusSeconds(300)).'</wsu:Expires></wsu:Timestamp>',
        ));

        $this->expectException(SecurityFault::class);
        $this->block()($context);
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
        $context = $this->context($this->envelope(
            $this->timestamp(
                $this->fmt($now),
                $this->fmt($now->plusSeconds(300)),
            ),
        ));

        $this->expectNotToPerformAssertions();
        $this->block()($context);
    }

    public function test_a_second_precision_timestamp_parses(): void
    {
        $now = $this->instant(self::NOW);
        $context = $this->context($this->envelope(
            $this->timestamp(
                $this->fmtSeconds($now),
                $this->fmtSeconds($now->plusSeconds(300)),
            ),
        ));

        $this->expectNotToPerformAssertions();
        $this->block()($context);
    }

    public function test_a_numeric_offset_timestamp_parses(): void
    {
        $now = $this->instant(self::NOW);
        $context = $this->context($this->envelope(
            $this->timestamp(
                $this->fmtOffset($now),
                $this->fmtOffset($now->plusSeconds(300)),
            ),
        ));

        $this->expectNotToPerformAssertions();
        $this->block()($context);
    }

    public function test_a_millisecond_offset_timestamp_parses(): void
    {
        $now = $this->instant(self::NOW);
        $context = $this->context($this->envelope(
            $this->timestamp(
                $this->fmtMilliOffset($now),
                $this->fmtMilliOffset($now->plusSeconds(300)),
            ),
        ));

        $this->expectNotToPerformAssertions();
        $this->block()($context);
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

        $this->expectNotToPerformAssertions();
        ((new ValidateTimestamp())->withClock($this->clock($now)))($this->context($xml, new SecurityProfile(clockSkew: 120)));
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
        $context = $this->context($this->envelope(
            $this->timestamp($this->fmt($frozen), $this->fmt($frozen->plusSeconds(300))),
        ));

        $this->expectNotToPerformAssertions();
        ((new ValidateTimestamp())->withClock($this->clock($frozen)))($context);
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
        return new WsseContext(Document::fromXmlString($xml), SoapVersion::Soap12, $profile ?? new SecurityProfile());
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
