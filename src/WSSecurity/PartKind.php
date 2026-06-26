<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity;

enum PartKind
{
    case Body;
    case Timestamp;
    case Element;
    case Id;
}
