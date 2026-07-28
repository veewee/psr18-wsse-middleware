<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

use Dom\Element;
use InvalidArgumentException;
use ParagonIE\HiddenString\HiddenString;
use Psl\DateTime\SecondsStyle;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Clock\Clock;
use Soap\Psr18WsseMiddleware\Clock\SystemClock;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\OpenSSL\Random;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityHeader;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\XmlSecurity\WsSecurityEncodingType;
use function VeeWee\Xml\Dom\Builder\attribute;
use function VeeWee\Xml\Dom\Builder\children;
use function VeeWee\Xml\Dom\Builder\namespaced_element;
use function VeeWee\Xml\Dom\Builder\value;

/**
 * Adds a wsse:UsernameToken to the Security header carrying the caller's credentials.
 *
 * PasswordText sends the password as cleartext and is only safe over TLS; the class does not enforce
 * TLS, that is the caller's responsibility. PasswordDigest sends Base64(SHA1(nonce + created +
 * password)) with the raw nonce in wsse:Nonce and the timestamp in wsu:Created, so the password never
 * travels in the clear and a captured digest cannot be replayed once the timestamp is stale. The nonce
 * is freshly generated for every invocation, and the same Created string feeds both the digest input
 * and the emitted element so a verifier can recompute the hash.
 */
final class Username implements OutboundAction
{
    private const NONCE_LENGTH = 16;
    private const TYPE_TEXT = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText';
    private const TYPE_DIGEST = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest';

    private readonly Random $random;
    private readonly Digest $digester;
    private Clock $clock;
    private ?HiddenString $password;

    public function __construct(
        private readonly string $username,
        #[SensitiveParameter]
        ?string $password = null,
        private bool $digest = false,
    ) {
        $this->password = $password === null ? null : new HiddenString($password);
        $this->random = new Random();
        $this->digester = new Digest();
        $this->clock = new SystemClock();
    }

    public function withPassword(#[SensitiveParameter] string $password): self
    {
        $clone = clone $this;
        $clone->password = new HiddenString($password);

        return $clone;
    }

    public function withDigest(bool $digest): self
    {
        $clone = clone $this;
        $clone->digest = $digest;

        return $clone;
    }

    public function withClock(Clock $clock): self
    {
        $clone = clone $this;
        $clone->clock = $clock;

        return $clone;
    }

    public function __invoke(WsseContext $context): void
    {
        if ($this->digest && $this->password === null) {
            throw new InvalidArgumentException('Digest mode requires a password.');
        }

        $header = SecurityHeader::forContext($context);
        $header->appendChildren($this->build());
    }

    /**
     * @return callable(Element): Element
     */
    private function build(): callable
    {
        $children = [
            namespaced_element(Namespaces::Wsse->value, Namespaces::Wsse->qualify('Username'), value($this->username)),
        ];

        if ($this->password !== null) {
            $children = [...$children, ...$this->passwordChildren($this->password->getString())];
        }

        return namespaced_element(
            Namespaces::Wsse->value,
            Namespaces::Wsse->qualify('UsernameToken'),
            children(...$children),
        );
    }

    /**
     * @return list<callable(Element): Element>
     */
    private function passwordChildren(#[SensitiveParameter] string $password): array
    {
        if (!$this->digest) {
            return [
                namespaced_element(
                    Namespaces::Wsse->value,
                    Namespaces::Wsse->qualify('Password'),
                    attribute('Type', self::TYPE_TEXT),
                    value($password),
                ),
            ];
        }

        $nonce = $this->random->bytes(self::NONCE_LENGTH);
        $created = $this->clock->now()->toRfc3339(SecondsStyle::Milliseconds, useZ: true);
        $digest = base64_encode($this->digester->hash($nonce.$created.$password, DigestMethod::SHA1));

        return [
            namespaced_element(
                Namespaces::Wsse->value,
                Namespaces::Wsse->qualify('Password'),
                attribute('Type', self::TYPE_DIGEST),
                value($digest),
            ),
            namespaced_element(
                Namespaces::Wsse->value,
                Namespaces::Wsse->qualify('Nonce'),
                attribute('EncodingType', WsSecurityEncodingType::Base64Binary->value),
                value(base64_encode($nonce)),
            ),
            namespaced_element(
                Namespaces::Wsu->value,
                Namespaces::Wsu->qualify('Created'),
                value($created),
            ),
        ];
    }
}
