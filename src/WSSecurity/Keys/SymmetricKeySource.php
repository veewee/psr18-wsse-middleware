<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Keys;

use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;

/**
 * Where a block's symmetric key comes from: a wrapped session key, a pre-shared secret, or a key derived from
 * either. A recipe rather than a key: an instance is constructed once with the middleware and reused for every
 * message the plugin handles, so it must hold no key state of its own. The per-exchange key lives in the
 * ExchangeKeys the context carries.
 *
 * Two blocks share one key by being handed the same source object. Identity is the sharing mechanism, which is
 * why a policy asking for a signature and an encryption keyed off one xenc:EncryptedKey needs no keyword: the
 * caller passes the same object twice.
 *
 * Resolving is idempotent per exchange. The first caller mints the key and writes whatever token carries it;
 * the second gets the same key and no second token is written.
 */
interface SymmetricKeySource
{
    /**
     * @param KeyRequest $for how many bytes the calling block's algorithm takes, and whether that is a
     *        requirement or a preference
     */
    public function resolve(WsseContext $context, KeyRequest $for): SymmetricKey;
}
