<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Keys;

use LogicException;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use WeakMap;

/**
 * The symmetric keys of one request/response exchange: which source materialized which key, and which wire
 * identifier names which secret.
 *
 * One instance per exchange, shared by the outbound and the inbound direction and by nothing else. That scope is
 * load-bearing rather than a convenience: a process-wide cache would let a response verify against a secret
 * established in a different exchange, which is cross-exchange replay.
 *
 * Sources are keyed by object identity through a WeakMap, which is the platform's map-keyed-by-object and whose
 * weak keys never extend a source's lifetime. Passing the same source to two blocks is therefore what makes
 * them share a key.
 */
final class ExchangeKeys
{
    /** @var WeakMap<SymmetricKeySource, SymmetricKey> */
    private WeakMap $materialized;

    /** @var WeakMap<SymmetricKeySource, true> */
    private WeakMap $shared;

    /** @var array<non-empty-string, SessionKey> */
    private array $established = [];

    public function __construct()
    {
        /** @var WeakMap<SymmetricKeySource, SymmetricKey> */
        $this->materialized = new WeakMap();
        /** @var WeakMap<SymmetricKeySource, true> */
        $this->shared = new WeakMap();
    }

    /**
     * The key this source produced for this exchange, minting it on first call only. The minted key's wire
     * identifiers are established here rather than by the caller, so "every materialized key is resolvable
     * inbound" cannot be forgotten at a call site.
     *
     * @param callable(): SymmetricKey $mint
     */
    public function materialize(SymmetricKeySource $source, callable $mint): SymmetricKey
    {
        $existing = $this->materialized[$source] ?? null;
        if ($existing !== null) {
            // A second taker, so the key is shared from here on.
            $this->shared[$source] = true;

            return $existing;
        }

        $key = $mint();
        $this->materialized[$source] = $key;
        $this->establish($key->bytes, ...$key->wireIdentifiers);

        return $key;
    }

    /**
     * Whether anything else in this exchange has already taken this source's key.
     *
     * A block that is alone with a key may still write into the element carrying it; one sharing a key may not,
     * because whoever took it first may already have signed that element. Counted at the moment a block asks,
     * which is what makes the answer right in either block order: a block running before the one it shares with
     * is alone when it asks, and the element it wrote into is then covered as it finally stands.
     */
    public function isShared(SymmetricKeySource $source): bool
    {
        return isset($this->shared[$source]);
    }

    /**
     * Records that a secret is reachable under each of these wire identifiers, so an inbound ds:KeyInfo naming
     * one of them resolves to it. Registering the same identifier twice with the same secret is a no-op, which
     * is what lets both inbound blocks hold one pre-shared source.
     *
     * Binding an identifier to a *different* secret is refused rather than allowed to win. Identifiers reach
     * this method from keys minted locally and from configuration, never from a message, so a collision is a
     * deployment holding two secrets under one name rather than anything a peer can arrange. Silently keeping
     * the last would make an inbound reference resolve to whichever block happened to register last.
     *
     * @param non-empty-string ...$wireIdentifiers
     *
     * @throws LogicException
     */
    public function establish(SessionKey $key, string ...$wireIdentifiers): void
    {
        foreach ($wireIdentifiers as $identifier) {
            $bound = $this->established[$identifier] ?? null;
            if ($bound !== null && !hash_equals($bound->bytes(), $key->bytes())) {
                throw new LogicException(sprintf(
                    'The identifier "%s" is already established in this exchange under a different secret. '
                    .'Give each secret an identifier of its own.',
                    $identifier,
                ));
            }

            $this->established[$identifier] = $key;
        }
    }

    /**
     * Whether this exchange has established any secret at all.
     *
     * The inbound resolvers ask before reading a reference as a symmetric one, so a deployment that never
     * establishes a secret does no symmetric work: the certificate forms are read exactly as they were, with no
     * extra lookup per signature.
     */
    public function hasEstablished(): bool
    {
        return $this->established !== [];
    }

    /**
     * The secret an inbound reference names, or null when this exchange established none under that
     * identifier. Null rather than an exception: what an unresolvable reference means is the calling block's
     * decision, and every such refusal collapses into its one uniform failure.
     *
     * @param non-empty-string $wireIdentifier
     */
    public function resolve(string $wireIdentifier): ?SessionKey
    {
        return $this->established[$wireIdentifier] ?? null;
    }
}
