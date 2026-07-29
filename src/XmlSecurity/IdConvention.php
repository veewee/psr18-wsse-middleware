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
 *
 * It belongs at the seam where an engine is wired up and both halves are used, and nowhere further: it is
 * decomposed there, and each collaborator underneath takes the one capability it needs — a minter or a lookup,
 * naming which. Do not widen those to take a convention. There is no pair to mismatch in a class that only
 * resolves, and holding a minter it never uses is precisely what stops "this cannot mint" from being a fact
 * about the inbound path.
 */
interface IdConvention
{
    public function minter(): IdMinter;

    public function lookup(): IdLookup;
}
