<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Keys;

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

    /** @var array<non-empty-string, SessionKey> */
    private array $established = [];

    public function __construct()
    {
        /** @var WeakMap<SymmetricKeySource, SymmetricKey> */
        $this->materialized = new WeakMap();
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
            return $existing;
        }

        $key = $mint();
        $this->materialized[$source] = $key;
        $this->establish($key->bytes, ...$key->wireIdentifiers);

        return $key;
    }

    /**
     * Records that a secret is reachable under each of these wire identifiers, so an inbound ds:KeyInfo naming
     * one of them resolves to it. Registering the same identifier twice with the same secret is a no-op, which
     * is what lets both inbound blocks hold one pre-shared source.
     *
     * @param non-empty-string ...$wireIdentifiers
     */
    public function establish(SessionKey $key, string ...$wireIdentifiers): void
    {
        foreach ($wireIdentifiers as $identifier) {
            $this->established[$identifier] = $key;
        }
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
