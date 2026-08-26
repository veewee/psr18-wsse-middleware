<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

use Phpro\ResourceStream\ResourceStream;

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
     * How much of each part a signature covers, which decides both the transform a block declares and what
     * collect() composes.
     */
    public function coverage(): ExternalPartCoverage;

    /**
     * The octets a signature covers, which under a Complete coverage is the part's canonical header block
     * followed by its content, and under a Content coverage is the content alone.
     *
     * May be called more than once for the same message, and should return streams positioned at the start
     * every time. Sign-then-encrypt collects twice: the signature digests the plaintext, then encryption
     * replaces it. The engine rewinds every part before reading it, so this is the second of two guards
     * rather than the only one, and an implementation whose streams cannot rewind is the case it covers.
     */
    public function collect(): ExternalPartList;

    /**
     * The octets the part itself carries, which a cipher seals on the way out and opens on the way in.
     *
     * Identical to collect() under a Content coverage, and the two differ under a Complete one: a
     * CipherReference addresses the MIME part, so what sits there is the sealed form whatever the coverage
     * says about the plaintext inside it, while a signature covers the composition. An implementation that
     * composes nothing can return collect().
     */
    public function collectSealed(): ExternalPartList;

    /**
     * Adds a part the message did not arrive with, and returns it with the reference that now addresses it.
     *
     * The reference comes back rather than going in, because whatever addresses a part is this
     * implementation's own vocabulary: nothing above it invents one. A caller asks for somewhere to put bytes
     * and is told what to point at, so an implementation over something other than MIME need not produce
     * anything resembling a Content-ID.
     *
     * The name goes the other way, because it is the one thing about the part an implementation cannot work
     * out: these bytes mean something to whoever handed them over and nothing here. Several parts may share
     * one, since what tells them apart is the reference.
     *
     * It sits on this interface rather than on one of its own because replace() already asks for a store that
     * can be written to, so adding excludes no implementation that was viable before it.
     *
     * @param ResourceStream<resource> $content
     * @param non-empty-string         $mimeType
     * @param non-empty-string         $name     what the part is, for whoever reads the wire
     */
    public function add(ResourceStream $content, string $mimeType, string $name): ExternalPart;

    /**
     * Fully replaces each part it is handed, matched by reference, and touches nothing else.
     *
     * Outbound that is every collected part, since all of them are transformed. Inbound it is only the parts
     * the document actually named, so a part that arrived in the clear is absent here and must be left alone
     * rather than dropped.
     */
    public function replace(ExternalPartList $parts): void;
}
