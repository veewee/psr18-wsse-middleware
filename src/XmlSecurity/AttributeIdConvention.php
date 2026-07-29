<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

/**
 * An IdConvention driven by a single IdAttribute: both halves are built from that one value, so they cannot
 * address different attributes.
 *
 * The engine ships the `xml:id` case as its zero-configuration default. A profile supplies its own attribute —
 * the WS-Security one supplies wsu:Id, from its own layer, so no spec-specific namespace has to live here.
 */
final readonly class AttributeIdConvention implements IdConvention
{
    private AttributeIdMinter $minter;
    private AttributeIdLookup $lookup;

    public function __construct(IdAttribute $attribute)
    {
        $this->minter = new AttributeIdMinter($attribute);
        $this->lookup = new AttributeIdLookup($attribute);
    }

    /**
     * The W3C-standard `xml:id`, so a standalone caller signs or encrypts with no configuration at all.
     */
    public static function xmlId(): self
    {
        return new self(IdAttribute::xmlId());
    }

    public function minter(): IdMinter
    {
        return $this->minter;
    }

    public function lookup(): IdLookup
    {
        return $this->lookup;
    }
}
