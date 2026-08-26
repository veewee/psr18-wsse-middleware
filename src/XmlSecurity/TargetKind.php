<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

enum TargetKind
{
    case Element;
    case Id;

    /**
     * An element addressed by where it sits: an ordered list of qualified names walked from the document
     * element down. Unlike Element, which finds the name anywhere, a path is satisfied only by the element in
     * that position, so one carrying the same name elsewhere never stands in for it.
     */
    case Path;
}
