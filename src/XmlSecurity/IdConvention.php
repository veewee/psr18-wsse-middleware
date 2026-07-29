<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

/**
 * One id convention, handed over as a pair: how a node gets its referenceable id, and how a reference resolves
 * back to that node. The two are inseparable — a signature that mints wsu:Id and resolves xml:id produces
 * references nobody can follow — so the engine takes the pair rather than two independent arguments, and a
 * mismatch stops being something a caller can express.
 *
 * Implement this to add a convention of your own; implementing it means supplying both halves, which is the
 * point.
 */
interface IdConvention
{
    public function minter(): IdMinter;

    public function lookup(): IdLookup;
}
