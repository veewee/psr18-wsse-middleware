<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Inbound;

use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;

/**
 * A self-configuring block that reads and processes one security concern of the inbound message. Each
 * block receives the per-message context and either returns (success) or throws one uniform security
 * fault (failure). Some blocks mutate the document in place (Decrypt rewrites encrypted parts to
 * plaintext); none expose plaintext or verification detail on failure, so the engine is never a padding
 * or validation oracle for a peer.
 *
 * The inbound analogue of OutboundAction. The block list is the declarative inbound contract; the
 * middleware invokes each block exactly once per message. Blocks carry their services by constructor
 * injection; only the per-message state lives in WsseContext.
 */
interface InboundAction
{
    /**
     * @throws \Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault
     */
    public function __invoke(WsseContext $context): void;
}
