<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Wsse;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespace;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdResolver;
use Symfony\Component\Uid\Uuid;
use Throwable;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\namespaced_attribute;

/**
 * Mints a wsu:Id value that is unique within a document and stamps it onto an element, so signing and
 * encryption can later reference exactly that element by id. A v4 UUID gives uniqueness without any
 * shared state; the "id-" prefix makes the value a valid XML NCName (which cannot start with a digit).
 */
final class WsuIdMinter
{
    /**
     * @return non-empty-string the minted id, without the '#' fragment prefix
     *
     * @throws WsseHeaderException when the element cannot carry the attribute
     */
    public function mint(Element $element, Document $document): string
    {
        $id = $this->uniqueId($document);

        try {
            namespaced_attribute(WsseNamespace::Wsu->value, WsseNamespace::Wsu->qualify('Id'), $id)($element);
        } catch (Throwable $exception) {
            throw WsseHeaderException::idStampFailed($exception->getMessage());
        }

        return $id;
    }

    /**
     * @return non-empty-string
     */
    private function uniqueId(Document $document): string
    {
        // A v4 UUID collision is effectively unreachable; the guard guarantees the value is free (and not a
        // pre-existing duplicate) before stamping.
        do {
            $id = 'id-'.Uuid::v4()->toRfc4122();
        } while (!WsuIdResolver::isFree($document, $id));

        return $id;
    }
}
