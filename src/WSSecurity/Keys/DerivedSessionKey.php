<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Keys;

use Dom\Element;
use InvalidArgumentException;
use Soap\Psr18WsseMiddleware\OpenSSL\P_SHA1;
use Soap\Psr18WsseMiddleware\OpenSSL\Random;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\LocalTokenKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\DerivedKeyToken;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdConvention;

/**
 * A key derived from another symmetric key with P_SHA1, carried as a wsc:DerivedKeyToken. This is what a policy
 * asking for sp:RequireDerivedKeys wants: the token both sides share is never used to sign or encrypt directly,
 * and each use gets a key of its own derived from it.
 *
 * The shape falls out of composition rather than configuration. Two of these over one WrappedSessionKey are two
 * derived keys off one xenc:EncryptedKey, which is exactly the wire a derived-keys policy describes, and nothing
 * in the wiring says "derive twice".
 *
 * The length is not a constructor argument: the consuming block's algorithm defines it, and it arrives with the
 * request. The label and the offset are, because they are per-token wire choices with no value to derive them
 * from.
 */
final class DerivedSessionKey implements SymmetricKeySource
{
    /**
     * The label both dialects default to: the specification's own name, written twice. A peer that derives with
     * anything else says so in the token it sends, which is read back off the element rather than assumed.
     */
    public const string DEFAULT_LABEL = 'WS-SecureConversationWS-SecureConversation';

    /**
     * A derived key is never shorter than this. Sixteen bytes is the narrowest key any algorithm this package
     * emits takes, so a request below it is a mis-wired block rather than a peer's choice.
     */
    private const int MINIMUM_LENGTH = 16;

    /**
     * The nonce length WSS4J and CXF emit, and what a receiver reads back off the element rather than assuming.
     */
    private const int NONCE_BYTES = 16;

    private readonly P_SHA1 $pSha1;
    private readonly Random $random;

    /** @var non-negative-int */
    private readonly int $offset;

    /**
     * @param ?string $label the derivation label. Null uses the specification's default, which is what every
     *        peer emitting this shape uses
     * @param int     $offset how far into the derived stream this key starts, for a peer that partitions one
     *        stream across several keys. A plain int rather than a refined one, because it is configuration
     *        and the check below is what makes it what the name says
     *
     * @throws InvalidArgumentException when the deriving key is itself derived, or the offset is negative or
     *         past what a derivation generates
     */
    public function __construct(
        private readonly SymmetricKeySource $from,
        private readonly ?string $label = null,
        int $offset = 0,
    ) {
        if ($from instanceof self) {
            // No peer emits chained derivation, and permitting it would let a response nest tokens until the
            // resolver ran out of stack. Refused where it is written rather than where it would unwind.
            throw new InvalidArgumentException('A derived key cannot be derived from another derived key.');
        }

        // The width is not known until a block asks, so the offset alone is what can be judged here. Refused
        // where it is written, because it is a configured number rather than a peer's, and a caller who wrote
        // it wants to hear about it at the line that wrote it.
        if ($offset < 0) {
            throw new InvalidArgumentException('A derivation offset must not be negative.');
        }

        if ($offset + self::MINIMUM_LENGTH > P_SHA1::MAX_GENERATED) {
            throw new InvalidArgumentException(sprintf(
                'A derivation generates at most %d bytes and an offset of %d leaves no room for a key.',
                P_SHA1::MAX_GENERATED,
                $offset,
            ));
        }

        $this->offset = $offset;
        $this->pSha1 = new P_SHA1();
        $this->random = new Random();
    }

    public function resolve(WsseContext $context, KeyRequest $for): SymmetricKey
    {
        $key = $context->keys()->materialize($this, fn (): SymmetricKey => $this->mint($context, $for));

        $for->enforce(
            $key,
            'The derived key this source carries',
            'Give each block a derived key of its own.',
        );

        return $key;
    }

    private function mint(WsseContext $context, KeyRequest $for): SymmetricKey
    {
        $width = $for->mintingWidth();
        if ($width < self::MINIMUM_LENGTH) {
            throw new InvalidArgumentException(sprintf(
                'A derived key must be at least %d bytes and this block asked for %d.',
                self::MINIMUM_LENGTH,
                $width,
            ));
        }

        $document = $context->document();
        $header = SecurityHeader::forContext($context);
        $version = $context->profile()->wsSecureConversation();

        // The deriving key's own width is not this key's: it is only a secret to derive from, and HMAC-based
        // derivation takes a key of any length.
        $deriving = $this->from->resolve($context, KeyRequest::preferably($width));

        // A fresh nonce per token. Repeating one repeats the derived key, so two messages would share one key.
        $nonce = $this->random->bytes(self::NONCE_BYTES);
        $label = $this->label === null || $this->label === '' ? self::DEFAULT_LABEL : $this->label;
        $derived = $this->pSha1->derive($deriving->bytes, $label.$nonce, $this->offset, $width);

        $token = (new DerivedKeyToken(
            $version,
            $deriving->keyIdentifier->apply($document),
            $label,
            $nonce,
            $this->offset,
            $width,
        ))->build($document);

        $header->appendChildren(static fn (): Element => $token);
        $wsuId = (new WsuIdConvention())->minter()->mint($token, $document);

        $reference = new LocalTokenKeyIdentifier($wsuId, $version);

        return new SymmetricKey($derived, $reference, ['#'.$wsuId]);
    }
}
