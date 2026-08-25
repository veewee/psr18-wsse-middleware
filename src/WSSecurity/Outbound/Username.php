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
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsSecurityEncodingType;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespaces;
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
 *
 * wsse:Nonce and wsu:Created can also be requested without the digest: peers that accept PasswordText
 * still use them to reject replays, and the token profile allows either element in any password mode.
 * Digest mode emits both whatever the withers say, since a digest a verifier cannot recompute is not a
 * token worth sending.
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
    private bool $nonce = false;
    private bool $created = false;

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

    /**
     * Digest mode emits the nonce whatever this says: the digest is computed over it.
     */
    public function withNonce(bool $nonce): self
    {
        $clone = clone $this;
        $clone->nonce = $nonce;

        return $clone;
    }

    /**
     * Digest mode emits the created instant whatever this says: the digest is computed over it.
     */
    public function withCreated(bool $created): self
    {
        $clone = clone $this;
        $clone->created = $created;

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
        $header = SecurityHeader::forContext($context);
        $header->appendChildren($this->build());
    }

    /**
     * @return callable(Element): Element
     */
    private function build(): callable
    {
        $password = $this->password?->getString();

        if ($this->digest && $password === null) {
            throw new InvalidArgumentException('Digest mode requires a password.');
        }

        // Digest mode hashes both markers, so it emits them even where the withers declined: a
        // wsse:PasswordDigest a verifier cannot recompute is not a token worth sending.
        $nonce = $this->nonce || $this->digest ? $this->random->bytes(self::NONCE_LENGTH) : null;
        $created = $this->created || $this->digest ? $this->createdAt() : null;

        return namespaced_element(
            WsseNamespaces::Wsse->value,
            WsseNamespaces::Wsse->qualify('UsernameToken'),
            // The token profile fixes the order as Username, Password, Nonce, Created.
            children(
                $this->child(WsseNamespaces::Wsse, 'Username', value($this->username)),
                ...$this->passwordChild($password, $nonce, $created),
                ...($nonce === null ? [] : [$this->child(
                    WsseNamespaces::Wsse,
                    'Nonce',
                    attribute('EncodingType', WsSecurityEncodingType::Base64Binary->value),
                    value(base64_encode($nonce)),
                )]),
                ...($created === null ? [] : [$this->child(WsseNamespaces::Wsu, 'Created', value($created))]),
            ),
        );
    }

    /**
     * The one child whose shape depends on the mode. The digest arm names the markers it hashes, which is
     * also what states their presence: digest mode generates both, so no arm can send a password the
     * declared Type does not describe.
     *
     * @return list<callable(Element): Element>
     */
    private function passwordChild(#[SensitiveParameter] ?string $password, #[SensitiveParameter] ?string $nonce, ?string $created): array
    {
        return match (true) {
            $password === null => [],
            !$this->digest => [$this->child(
                WsseNamespaces::Wsse,
                'Password',
                attribute('Type', self::TYPE_TEXT),
                value($password),
            )],
            $nonce !== null && $created !== null => [$this->child(
                WsseNamespaces::Wsse,
                'Password',
                attribute('Type', self::TYPE_DIGEST),
                value(base64_encode($this->digester->hash($nonce.$created.$password, DigestMethod::SHA1))),
            )],
        };
    }

    private function createdAt(): string
    {
        return $this->clock->now()->toRfc3339(SecondsStyle::Milliseconds, useZ: true);
    }

    /**
     * @param callable(Element): Element ...$configurators
     *
     * @return callable(Element): Element
     */
    private function child(WsseNamespaces $namespace, string $localName, callable ...$configurators): callable
    {
        return namespaced_element($namespace->value, $namespace->qualify($localName), ...$configurators);
    }
}
