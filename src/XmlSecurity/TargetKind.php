<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

enum TargetKind
{
    case Element;
    case Id;
}
