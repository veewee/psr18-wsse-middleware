<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;

/**
 * A self-configuring building block that adds one WSSE token or security operation to the outbound
 * message. Each block locates or creates the wsse:Security header, appends its element, and returns.
 * The block list is the declarative outbound contract; the order of blocks in the list is preserved.
 *
 * Blocks do not de-duplicate: calling one twice on the same document produces two token elements. The
 * middleware is responsible for invoking each block exactly once per message.
 */
interface OutboundAction
{
    /**
     * @throws \Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException
     */
    public function __invoke(WsseContext $context): void;
}
