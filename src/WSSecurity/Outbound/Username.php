<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

use Dom\Element;
use InvalidArgumentException;
use Psl\DateTime\SecondsStyle;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\OpenSSL\Random;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Clock\Clock;
use Soap\Psr18WsseMiddleware\WSSecurity\Clock\SystemClock;
use Soap\Psr18WsseMiddleware\WSSecurity\Wsse\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespace;
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
    private const ENCODING_BASE64 = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary';

    private readonly Random $random;
    private readonly Digest $digester;
    private Clock $clock;

    public function __construct(
        private readonly string $username,
        #[SensitiveParameter]
        private ?string $password = null,
        private bool $digest = false,
    ) {
        $this->random = new Random();
        $this->digester = new Digest();
        $this->clock = new SystemClock();
    }

    public function withPassword(#[SensitiveParameter] string $password): self
    {
        $clone = clone $this;
        $clone->password = $password;

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

        $header = SecurityHeader::locateOrCreate($context->document(), $context->soapVersion());
        $header->appendChildren($this->build());
    }

    /**
     * @return callable(Element): Element
     */
    private function build(): callable
    {
        $children = [
            namespaced_element(WsseNamespace::Wsse->value, WsseNamespace::Wsse->qualify('Username'), value($this->username)),
        ];

        if ($this->password !== null) {
            $children = [...$children, ...$this->passwordChildren($this->password)];
        }

        return namespaced_element(
            WsseNamespace::Wsse->value,
            WsseNamespace::Wsse->qualify('UsernameToken'),
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
                    WsseNamespace::Wsse->value,
                    WsseNamespace::Wsse->qualify('Password'),
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
                WsseNamespace::Wsse->value,
                WsseNamespace::Wsse->qualify('Password'),
                attribute('Type', self::TYPE_DIGEST),
                value($digest),
            ),
            namespaced_element(
                WsseNamespace::Wsse->value,
                WsseNamespace::Wsse->qualify('Nonce'),
                attribute('EncodingType', self::ENCODING_BASE64),
                value(base64_encode($nonce)),
            ),
            namespaced_element(
                WsseNamespace::Wsu->value,
                WsseNamespace::Wsu->qualify('Created'),
                value($created),
            ),
        ];
    }
}
