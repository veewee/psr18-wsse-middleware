<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

/**
 * Where external parts come from and where the transformed ones go back to.
 *
 * The blocks call this; the engine never does. That is deliberate: an engine that called out mid-operation
 * would be handing control, and potentially key material, to caller code in the middle of a crypto operation.
 * Instead a block reads the parts, hands bytes to the engine, and writes the result back afterwards.
 *
 * The seam exists to keep foreign types out of this package's signatures rather than to abstract a variation.
 * An implementation over some other package's storage is the caller's business, and this package ships one.
 */
interface ExternalParts
{
    /**
     * How much of each part the compositions this adapter hands out and takes back cover.
     *
     * No block reads it yet: each one names the content-only transform and type directly. The seam takes it
     * now because adding a method to an interface breaks every implementation of it, and nothing has tagged.
     */
    public function coverage(): ExternalPartCoverage;

    /**
     * May be called more than once for the same message, and should return streams positioned at the start
     * every time.
     *
     * Sign-then-encrypt collects twice: the signature digests the plaintext, then encryption replaces it. The
     * engine rewinds every part before reading it, so this is the second of two guards rather than the only
     * one, and an implementation whose streams cannot rewind is the case it covers.
     */
    public function collect(): ExternalPartList;

    /**
     * Fully replaces each part it is handed, matched by reference, and touches nothing else.
     *
     * Outbound that is every collected part, since all of them are transformed. Inbound it is only the parts
     * the document actually named, so a part that arrived in the clear is absent here and must be left alone
     * rather than dropped.
     */
    public function replace(ExternalPartList $parts): void;
}
